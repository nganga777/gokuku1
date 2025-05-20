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

	srv := &http.Server{
		Handler:      r,
		Addr:         ":3000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Server started on :3000")
	log.Fatal(srv.ListenAndServe())
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Initialize logging entry
	logEntry := createLogEntry(req, r)
	messageID := fmt.Sprintf("<%s@%s>", generateUUID(), req.SMTPConfig.Host)

	// Process proxy and get afterProxyIP if needed
	proxyUsed, afterProxyIP, proxyErr := processProxy(&req, logEntry)
	if proxyErr != nil {
		logEntry["proxyError"] = proxyErr.Error()
		logEntry["fallbackToDirect"] = true
	}

	// Send email
	err := sendEmail(req, logEntry, proxyUsed)
	if err != nil {
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
	}

	// Success response
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
	} else {
		logEntry["noProxyConfigured"] = true
	}

	return logEntry
}

func processProxy(req *EmailRequest, logEntry map[string]interface{}) (bool, string, error) {
	if req.ProxyConfig == nil || req.ProxyConfig.Host == "" {
		logEntry["connectionType"] = "direct"
		return false, "", nil
	}

	// Get public IP through proxy
	ip, err := getPublicIPViaProxy(req.ProxyConfig)
	if err != nil {
		logEntry["connectionType"] = "direct"
		return false, "", err
	}

	logEntry["proxyUsed"] = true
	logEntry["connectionType"] = "proxy"
	return true, ip, nil
}

func getPublicIPViaProxy(proxyConfig *ProxyConfig) (string, error) {
	dialer, err := createProxyDialer(proxyConfig)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func createProxyDialer(proxyConfig *ProxyConfig) (proxy.Dialer, error) {
	baseDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	auth := &proxy.Auth{
		User:     proxyConfig.Username,
		Password: proxyConfig.Password,
	}

	return proxy.SOCKS5(
		"tcp",
		fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port),
		auth,
		baseDialer,
	)
}

func sendEmail(req EmailRequest, logs map[string]interface{}, useProxy bool) error {
	var dialer proxy.Dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	if useProxy && req.ProxyConfig != nil {
		var err error
		dialer, err = createProxyDialer(req.ProxyConfig)
		if err != nil {
			return fmt.Errorf("proxy connection failed: %v", err)
		}
	}

	// Verify connection
	if err := verifySMTPConnection(req, dialer, logs); err != nil {
		return err
	}

	// Create message
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

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if req.SMTPConfig.Secure {
		if err = client.StartTLS(&tls.Config{ServerName: req.SMTPConfig.Host}); err != nil {
			return err
		}
	}

	if err = client.Auth(auth); err != nil {
		return err
	}

	if err = client.Mail(from.Address); err != nil {
		return err
	}
	if err = client.Rcpt(to.Address); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = msg.WriteTo(w)
	return err
}

func verifySMTPConnection(req EmailRequest, dialer proxy.Dialer, logs map[string]interface{}) error {
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", req.SMTPConfig.Host, req.SMTPConfig.Port))
	if err != nil {
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, req.SMTPConfig.Host)
	if err != nil {
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("SMTP client creation failed: %v", err)
	}
	defer client.Close()

	if err := client.Noop(); err != nil {
		logs["connectionVerified"] = false
		logs["verifyError"] = err.Error()
		return fmt.Errorf("SMTP noop failed: %v", err)
	}

	logs["connectionVerified"] = true
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
