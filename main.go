package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/proxy"
)

type SMTPAuth struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type SMTPConfig struct {
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	Secure bool     `json:"secure"`
	Auth   SMTPAuth `json:"auth"`
}

type ProxyConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type EmailRequest struct {
	SMTPConfig   SMTPConfig   `json:"smtpConfig"`
	ProxyConfig  *ProxyConfig `json:"proxyConfig,omitempty"`
	SenderName   string       `json:"senderName"`
	SenderEmail  string       `json:"senderEmail"`
	ToEmail      string       `json:"toEmail"`
	Subject      string       `json:"subject"`
	Code         string       `json:"code"`
	OriginalIP   string       `json:"originalIp,omitempty"`
}

type EmailResponse struct {
	Success   bool                   `json:"success"`
	MessageID string                 `json:"messageId,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Logs      map[string]interface{} `json:"logs"`
}

var (
	connectionPool = sync.Pool{
		New: func() interface{} {
			return &net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 0,
			}
		},
	}
	proxyDialerPool = sync.Pool{
		New: func() interface{} {
			return &struct {
				dialer proxy.Dialer
				mu     sync.Mutex
			}{}
		},
	}
)

const (
	maxRetries        = 3
	initialRetryDelay = 2 * time.Second
	smtpDialTimeout   = 15 * time.Second
	smtpCmdTimeout   = 10 * time.Second
	smtpDataTimeout  = 15 * time.Second
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/send-email", sendEmailHandler).Methods("POST")
	r.Use(loggingMiddleware)

	srv := &http.Server{
		Handler:      r,
		Addr:         ":3000",
		WriteTimeout: 45 * time.Second,
		ReadTimeout:  45 * time.Second,
	}

	log.Println("Server started on :3000")
	log.Fatal(srv.ListenAndServe())
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)
		
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start)
		log.Printf("Completed %s %s in %v with status %d", 
			r.Method, r.URL.Path, duration, rw.status)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Entering sendEmailHandler")
	
	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	logEntry := createLogEntry(req, r)
	messageID := fmt.Sprintf("<%s@%s>", generateUUID(), req.SMTPConfig.Host)
	logEntry["messageId"] = messageID

	proxyUsed := req.ProxyConfig != nil && req.ProxyConfig.Host != ""
	if proxyUsed {
		logEntry["proxyUsed"] = true
		go func() {
			if ip, err := getProxyIP(req.ProxyConfig); err == nil {
				logEntry["afterProxyIp"] = ip
				log.Printf("Proxy IP detected: %s", ip)
			} else {
				log.Printf("Proxy IP detection failed (non-critical): %v", err)
			}
		}()
	}

	err := sendEmailWithRetry(req, logEntry, proxyUsed)
	if err != nil {
		log.Printf("Email sending failed: %v", err)
		response := EmailResponse{
			Success: false,
			Error:   err.Error(),
			Logs:    logEntry,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := EmailResponse{
		Success:   true,
		MessageID: messageID,
		Logs:      logEntry,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sendEmailWithRetry(req EmailRequest, logs map[string]interface{}, useProxy bool) error {
	var lastErr error
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Attempt %d/%d to send email", attempt, maxRetries)
		err := sendEmailWithIsolation(req, logs, useProxy)
		if err == nil {
			return nil
		}
		
		lastErr = err
		if attempt < maxRetries {
			retryDelay := time.Duration(attempt) * initialRetryDelay
			log.Printf("Attempt %d failed, retrying in %v: %v", attempt, retryDelay, err)
			time.Sleep(retryDelay)
		}
	}
	
	return fmt.Errorf("after %d attempts, last error: %v", maxRetries, lastErr)
}

func sendEmailWithIsolation(req EmailRequest, logs map[string]interface{}, useProxy bool) error {
	log.Println("Starting isolated email sending process")
	
	baseDialer := connectionPool.Get().(*net.Dialer)
	defer connectionPool.Put(baseDialer)

	var dialer proxy.Dialer = baseDialer

	if useProxy && req.ProxyConfig != nil {
		proxyDialerWrapper := proxyDialerPool.Get().(*struct {
			dialer proxy.Dialer
			mu     sync.Mutex
		})
		defer proxyDialerPool.Put(proxyDialerWrapper)

		proxyDialerWrapper.mu.Lock()
		defer proxyDialerWrapper.mu.Unlock()

		var err error
		if proxyDialerWrapper.dialer == nil {
			proxyDialerWrapper.dialer, err = createProxyDialer(req.ProxyConfig)
		}
		if err != nil {
			return fmt.Errorf("proxy connection failed: %v", err)
		}
		dialer = proxyDialerWrapper.dialer
	}

	addr := fmt.Sprintf("%s:%d", req.SMTPConfig.Host, req.SMTPConfig.Port)
	auth := smtp.PlainAuth("", req.SMTPConfig.Auth.User, req.SMTPConfig.Auth.Password, req.SMTPConfig.Host)

	ctx, cancel := context.WithTimeout(context.Background(), smtpDialTimeout)
	defer cancel()

	conn, err := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer func() {
		if err := client.Quit(); err != nil {
			log.Printf("Error closing SMTP client: %v", err)
		}
	}()

	if err := clientSetDeadline(client, smtpCmdTimeout); err != nil {
		return err
	}
	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("initial EHLO failed: %v", err)
	}

	if req.SMTPConfig.Port == 587 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName:         req.SMTPConfig.Host,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %v", err)
			}
		}
	}

	if err := clientSetDeadline(client, smtpCmdTimeout); err != nil {
		return err
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %v", err)
	}

	if err := clientSetDeadline(client, smtpCmdTimeout); err != nil {
		return err
	}
	from := mail.Address{Name: req.SenderName, Address: req.SenderEmail}
	to := mail.Address{Address: req.ToEmail}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	if err := client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("RCPT TO failed: %v", err)
	}

	if err := clientSetDeadline(client, smtpDataTimeout); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %v", err)
	}
	defer wc.Close()

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from.String()))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to.String()))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	msg.WriteString("Content-Type: text/html\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("<p>Your verification code is: <strong>%s</strong></p>", req.Code))

	if _, err := msg.WriteTo(wc); err != nil {
		return fmt.Errorf("failed to write email body: %v", err)
	}

	log.Println("Email successfully sent")
	return nil
}

func clientSetDeadline(client *smtp.Client, timeout time.Duration) error {
	return client.SetDeadline(time.Now().Add(timeout))
}

func createProxyDialer(proxyConfig *ProxyConfig) (proxy.Dialer, error) {
	return proxy.SOCKS5(
		"tcp",
		fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port),
		&proxy.Auth{
			User:     proxyConfig.Username,
			Password: proxyConfig.Password,
		},
		&net.Dialer{
			Timeout:   smtpDialTimeout,
			KeepAlive: 0,
		},
	)
}

func getProxyIP(proxyConfig *ProxyConfig) (string, error) {
	dialer, err := createProxyDialer(proxyConfig)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

func createLogEntry(req EmailRequest, r *http.Request) map[string]interface{} {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	return map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"originalIp": func() string {
			if req.OriginalIP != "" {
				return req.OriginalIP
			}
			return clientIP
		}(),
		"beforeProxyIp": clientIP,
		"requestData": map[string]string{
			"toEmail":     req.ToEmail,
			"senderEmail": req.SenderEmail,
			"subject":     req.Subject,
		},
		"proxyConfig": func() interface{} {
			if req.ProxyConfig != nil {
				return map[string]interface{}{
					"host":    req.ProxyConfig.Host,
					"port":    req.ProxyConfig.Port,
					"hasAuth": req.ProxyConfig.Username != "",
				}
			}
			return nil
		}(),
	}
}

func generateUUID() string {
	return fmt.Sprintf("%x%x%x%x%x",
		time.Now().UnixNano(),
		os.Getpid(),
		[]byte{1, 2, 3, 4},
		[]byte{5, 6, 7, 8},
		[]byte{9, 0, 1, 2},
	)
}
