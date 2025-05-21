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
	Username string `json:"username,omitempty"
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

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/send-email", sendEmailHandler).Methods("POST")

	// Add middleware for request logging
	r.Use(loggingMiddleware)

	srv := &http.Server{
		Handler:      r,
		Addr:         ":3000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Server started on :3000")
	log.Fatal(srv.ListenAndServe())
}

// Middleware to log incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)
		
		// Create a response writer wrapper to capture status code
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
	log.Println("Successfully decoded request body")

	// Initialize logging entry
	logEntry := createLogEntry(req, r)
	messageID := fmt.Sprintf("<%s@%s>", generateUUID(), req.SMTPConfig.Host)
	logEntry["messageId"] = messageID
	log.Printf("Created message ID: %s", messageID)

	// Process proxy - skip verification since we know it works for SMTP
	proxyUsed := req.ProxyConfig != nil && req.ProxyConfig.Host != ""
	if proxyUsed {
		logEntry["proxyUsed"] = true
		logEntry["connectionType"] = "proxy"
		log.Println("Proxy configured, will attempt to use for SMTP")
	} else {
		logEntry["connectionType"] = "direct"
		log.Println("No proxy configured, using direct connection")
	}

	// Log SMTP config (without password)
	log.Printf("SMTP Config - Host: %s, Port: %d, Secure: %t, User: %s", 
		req.SMTPConfig.Host, req.SMTPConfig.Port, req.SMTPConfig.Secure, req.SMTPConfig.Auth.User)

	// Send email
	log.Println("Attempting to send email...")
	err := sendEmail(req, logEntry, proxyUsed)
	if err != nil {
		log.Printf("Email sending failed: %v", err)
		response := EmailResponse{
			Success: false,
			Error:   err.Error(),
			Logs:    logEntry,
		}
		logEntry["finalOutcome"] = "error"
		logEntry["smtpSuccess"] = false
		logEntry["smtpError"] = err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Success response
	log.Println("Email sent successfully")
	logEntry["finalOutcome"] = "success"
	logEntry["smtpSuccess"] = true
	response := EmailResponse{
		Success:   true,
		MessageID: messageID,
		Logs:      logEntry,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func createLogEntry(req EmailRequest, r *http.Request) map[string]interface{} {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	logEntry := map[string]interface{}{
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
	}

	if req.ProxyConfig != nil {
		logEntry["proxyConfig"] = map[string]interface{}{
			"host":    req.ProxyConfig.Host,
			"port":    req.ProxyConfig.Port,
			"hasAuth": req.ProxyConfig.Username != "",
		}
		log.Printf("Proxy config present - Host: %s, Port: %d", 
			req.ProxyConfig.Host, req.ProxyConfig.Port)
	} else {
		logEntry["noProxyConfigured"] = true
		log.Println("No proxy configuration provided")
	}

	return logEntry
}

func sendEmail(req EmailRequest, logs map[string]interface{}, useProxy bool) error {
	log.Println("Starting email sending process")
	
	var dialer proxy.Dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	if useProxy && req.ProxyConfig != nil {
		log.Println("Using proxy for SMTP connection")
		var err error
		dialer, err = createProxyDialer(req.ProxyConfig)
		if err != nil {
			return fmt.Errorf("proxy connection failed: %v", err)
		}
	}

	addr := fmt.Sprintf("%s:%d", req.SMTPConfig.Host, req.SMTPConfig.Port)
	auth := smtp.PlainAuth("", req.SMTPConfig.Auth.User, req.SMTPConfig.Auth.Password, req.SMTPConfig.Host)

	log.Printf("Dialing SMTP server at %s", addr)
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server: %v", err)
	}
	defer conn.Close()

	// Create client with longer timeout
	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Close()

	// Send initial EHLO
	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("initial EHLO failed: %v", err)
	}

	// Handle STARTTLS for port 587
	if req.SMTPConfig.Port == 587 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			log.Println("Server supports STARTTLS, attempting upgrade")
			tlsConfig := &tls.Config{
				ServerName:         req.SMTPConfig.Host,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %v", err)
			}
			log.Println("STARTTLS completed successfully")
		} else {
			log.Println("Server does not support STARTTLS, continuing without encryption")
		}
	}

	// Authenticate
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %v", err)
	}

	// Set sender and recipient
	from := mail.Address{Name: req.SenderName, Address: req.SenderEmail}
	to := mail.Address{Address: req.ToEmail}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	if err := client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("RCPT TO failed: %v", err)
	}

	// Send email body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %v", err)
	}
	defer w.Close()

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from.String()))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to.String()))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	msg.WriteString("Content-Type: text/html\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("<p>Your verification code is: <strong>%s</strong></p>", req.Code))

	if _, err := msg.WriteTo(w); err != nil {
		return fmt.Errorf("failed to write email body: %v", err)
	}

	log.Println("Email successfully sent")
	return nil
}

func createProxyDialer(proxyConfig *ProxyConfig) (proxy.Dialer, error) {
	log.Println("Creating base dialer")
	baseDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	auth := &proxy.Auth{
		User:     proxyConfig.Username,
		Password: proxyConfig.Password,
	}

	log.Printf("Creating SOCKS5 dialer for %s:%d", proxyConfig.Host, proxyConfig.Port)
	dialer, err := proxy.SOCKS5(
		"tcp",
		fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port),
		auth,
		baseDialer,
	)
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		return nil, err
	}

	return dialer, nil
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
