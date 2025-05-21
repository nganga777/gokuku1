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

	// Process proxy and get afterProxyIP if needed
	proxyUsed, afterProxyIP, proxyErr := processProxy(&req, logEntry)
	if proxyErr != nil {
		log.Printf("Proxy processing error: %v", proxyErr)
		logEntry["proxyError"] = proxyErr.Error()
		logEntry["fallbackToDirect"] = true
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

	// Add afterProxyIP if proxy was used successfully
	if proxyUsed && afterProxyIP != "" {
		logEntry["afterProxyIp"] = afterProxyIP
		log.Printf("Proxy used successfully. After proxy IP: %s", afterProxyIP)
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

func processProxy(req *EmailRequest, logEntry map[string]interface{}) (bool, string, error) {
	if req.ProxyConfig == nil || req.ProxyConfig.Host == "" {
		logEntry["connectionType"] = "direct"
		log.Println("No proxy configured, using direct connection")
		return false, "", nil
	}

	log.Println("Attempting to connect via proxy...")
	// Get public IP through proxy
	ip, err := getPublicIPViaProxy(req.ProxyConfig)
	if err != nil {
		logEntry["connectionType"] = "direct"
		log.Printf("Proxy connection failed, falling back to direct: %v", err)
		return false, "", err
	}

	logEntry["proxyUsed"] = true
	logEntry["connectionType"] = "proxy"
	log.Printf("Successfully connected via proxy. Public IP: %s", ip)
	return true, ip, nil
}

func getPublicIPViaProxy(proxyConfig *ProxyConfig) (string, error) {
	log.Printf("Creating proxy dialer for %s:%d", proxyConfig.Host, proxyConfig.Port)
	dialer, err := createProxyDialer(proxyConfig)
	if err != nil {
		log.Printf("Failed to create proxy dialer: %v", err)
		return "", err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Dialing through proxy: %s %s", network, addr)
			return dialer.Dial(network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	log.Println("Making request to api.ipify.org to determine public IP")
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		log.Printf("Failed to get public IP via proxy: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code from ipify: %d", resp.StatusCode)
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return "", err
	}

	ip := string(body)
	log.Printf("Successfully retrieved public IP via proxy: %s", ip)
	return ip, nil
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
			log.Printf("Failed to create proxy dialer for SMTP: %v", err)
			return fmt.Errorf("proxy connection failed: %v", err)
		}
	} else {
		log.Println("Using direct connection for SMTP")
	}

	// Verify connection
	log.Println("Verifying SMTP connection")
	if err := verifySMTPConnection(req, dialer, logs); err != nil {
		log.Printf("SMTP connection verification failed: %v", err)
		return err
	}

	// Create message
	log.Println("Creating email message")
	from := mail.Address{Name: req.SenderName, Address: req.SenderEmail}
	to := mail.Address{Address: req.ToEmail}

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from.String()))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to.String()))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	msg.WriteString("Content-Type: text/html\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("<p>Your verification code is: <strong>%s</strong></p>", req.Code))

	// Connect and send
	addr := fmt.Sprintf("%s:%d", req.SMTPConfig.Host, req.SMTPConfig.Port)
	auth := smtp.PlainAuth("", req.SMTPConfig.Auth.User, req.SMTPConfig.Auth.Password, req.SMTPConfig.Host)

	log.Printf("Dialing SMTP server at %s", addr)
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to dial SMTP server: %v", err)
		return err
	}
	defer conn.Close()
	log.Println("Successfully connected to SMTP server")

	log.Println("Creating SMTP client")
	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		log.Printf("Failed to create SMTP client: %v", err)
		return err
	}
	defer client.Close()
	log.Println("SMTP client created successfully")

	if req.SMTPConfig.Secure {
		log.Println("Starting TLS")
		if err = client.StartTLS(&tls.Config{ServerName: req.SMTPConfig.Host}); err != nil {
			log.Printf("StartTLS failed: %v", err)
			return err
		}
		log.Println("TLS established successfully")
	}

	log.Println("Authenticating with SMTP server")
	if err = client.Auth(auth); err != nil {
		log.Printf("SMTP authentication failed: %v", err)
		return err
	}
	log.Println("Authentication successful")

	log.Printf("Setting sender: %s", from.Address)
	if err = client.Mail(from.Address); err != nil {
		log.Printf("MAIL FROM command failed: %v", err)
		return err
	}

	log.Printf("Setting recipient: %s", to.Address)
	if err = client.Rcpt(to.Address); err != nil {
		log.Printf("RCPT TO command failed: %v", err)
		return err
	}

	log.Println("Preparing to send email data")
	w, err := client.Data()
	if err != nil {
		log.Printf("DATA command failed: %v", err)
		return err
	}
	defer w.Close()

	log.Println("Writing email content")
	_, err = msg.WriteTo(w)
	if err != nil {
		log.Printf("Failed to write email content: %v", err)
		return err
	}
	log.Println("Email content written successfully")

	return nil
}

func verifySMTPConnection(req EmailRequest, dialer proxy.Dialer, logs map[string]interface{}) error {
	addr := fmt.Sprintf("%s:%d", req.SMTPConfig.Host, req.SMTPConfig.Port)
	log.Printf("Verifying SMTP connection to %s", addr)
	
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("SMTP connection verification failed at dial: %v", err)
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()
	log.Println("SMTP connection established for verification")

	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		log.Printf("SMTP client creation failed during verification: %v", err)
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("SMTP client creation failed: %v", err)
	}
	defer client.Close()
	log.Println("SMTP client created for verification")

	log.Println("Sending NOOP command to verify connection")
	if err := client.Noop(); err != nil {
		log.Printf("SMTP NOOP command failed: %v", err)
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("SMTP noop failed: %v", err)
	}

	logs["connectionVerified"] = true
	log.Println("SMTP connection verified successfully")
	return nil
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
