package main

import (
	"crypto/sha1" //nolint:gosec
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type Handler struct {
	files      fs.FS
	envContext map[string]string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/status"):
		h.statusHandler(w, r)
	case strings.HasPrefix(r.URL.Path, "/apps/"):
		h.templateHandler(w, r)
	case r.URL.Path == "/sse":
		h.serverSentEventHandler(w, r)
	case r.URL.Path == "/websocket":
		h.webSocketHandler(w, r)
	default:
		h.echoHandler(w, r)
	}
}

// echoHandler gathers information about the incoming request and returns it as a JSON response.
func (h *Handler) echoHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling echo request", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)
	info := h.collectRequestInfo(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("Error reading body", "error", err)
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		info["body"] = string(body)
	}

	h.processRequestBody(r, body, info)

	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		slog.Error("Error marshaling JSON", "error", err)
		http.Error(w, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(jsonData)
}

func (h *Handler) collectRequestInfo(r *http.Request) map[string]any {
	info := map[string]any{
		"method":         r.Method,
		"url":            r.URL.String(),
		"proto":          r.Proto,
		"headers":        r.Header,
		"host":           r.Host,
		"remote":         r.RemoteAddr,
		"content_length": r.ContentLength,
	}

	if r.URL.RawQuery != "" {
		info["query"] = r.URL.Query()
	}

	if r.TLS != nil {
		h.decodeTLSInfo(r, info)
	}

	authorization := r.Header.Get("Authorization")
	if authorization != "" {
		h.decodeAuthorizationInfo(authorization, info)
	}

	if cookies := r.Cookies(); len(cookies) > 0 {
		decodeCookies(cookies, info)
	}

	if h.envContext != nil {
		info["env"] = h.envContext
	}

	return info
}

func (h *Handler) processRequestBody(r *http.Request, body []byte, info map[string]any) {
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err == nil {
			info["form"] = values
		}
	}
}

// decodeTLSInfo extracts TLS information from the request.
func (h *Handler) decodeTLSInfo(r *http.Request, info map[string]any) {
	slog.Info("TLS connection", "version", tls.VersionName(r.TLS.Version), "cipher_suite", tls.CipherSuiteName(r.TLS.CipherSuite))
	var clientCerts string
	for _, cert := range r.TLS.PeerCertificates {
		clientCerts += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	info["tls"] = map[string]any{
		"version":                  tls.VersionName(r.TLS.Version),
		"alpn_negotiated_protocol": r.TLS.NegotiatedProtocol,
		"cipher_suite":             tls.CipherSuiteName(r.TLS.CipherSuite),
		"peer_certificates":        clientCerts,
	}
}

// decodeAuthorizationInfo extracts information from the Authorization header.
func (h *Handler) decodeAuthorizationInfo(authorization string, info map[string]any) {
	val := strings.SplitN(authorization, " ", 2)
	if len(val) != 2 {
		slog.Warn("Invalid authorization header format")
		return
	}

	authType := strings.ToLower(val[0])
	credentials := strings.TrimSpace(val[1])

	var err error
	switch authType {
	case "bearer":
		err = parseBearerAuth(credentials, info)
	case "basic":
		err = parseBasicAuth(credentials, info)
	default:
		slog.Warn("Unsupported authorization type", "type", authType)
		return
	}

	if err != nil {
		slog.Warn("Error parsing authorization header", "error", err)
		return
	}
}

// parseBearerAuth decodes a JWT token.
func parseBearerAuth(token string, info map[string]any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT token format")
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	header := map[string]any{}
	if err = json.Unmarshal(decodedHeader, &header); err != nil {
		return err
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	claims := map[string]any{}
	if err := json.Unmarshal(decodedPayload, &claims); err != nil {
		return err
	}

	jwt := map[string]any{
		"header": header,
		"claims": claims,
	}

	// Convert the `iat` and `exp` claims to ISO 8601 human readable format.
	for _, claim := range []string{"iat", "exp"} {
		if val, ok := claims[claim]; ok {
			if valFloat, ok := val.(float64); ok {
				jwt[claim+"_date"] = time.Unix(int64(valFloat), 0).Format(time.RFC3339)
			}
		}
	}

	info["jwt"] = jwt
	return nil
}

// parseBasicAuth decodes a basic authentication credentials.
func parseBasicAuth(encoded string, info map[string]any) error {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid basic auth format")
	}

	info["basic_auth"] = map[string]any{
		"username": parts[0],
		"password": parts[1],
	}
	return nil
}

func decodeCookies(cookies []*http.Cookie, info map[string]any) {
	c := map[string]string{}
	for _, cookie := range cookies {
		c[cookie.Name] = cookie.Value
	}
	info["cookies"] = c
}

// statusHandler returns a response with the provided status code.
// The status code is extracted from the URL path.
// If not provided, it returns 200 OK.
func (h *Handler) statusHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling status request", "url", r.URL.String())

	if r.URL.Path == "/status" {
		w.WriteHeader(http.StatusOK)
		return
	}

	re := regexp.MustCompile(`^/status/(\d\d\d)$`)
	match := re.FindStringSubmatch(r.URL.Path)
	if match == nil {
		slog.Warn("Error parsing status code /status/{code}")
		http.Error(w, "Invalid status code provided for /status/{code}. Code must be a 3-digit number.",
			http.StatusBadRequest)
		return
	}
	code, _ := strconv.Atoi(match[1])

	if r.Body != nil {
		var headers map[string]string
		if err := json.NewDecoder(r.Body).Decode(&headers); err != nil && err != io.EOF {
			slog.Warn("Error decoding JSON body", "error", err)
			http.Error(w, "Error decoding JSON body", http.StatusBadRequest)
			return
		}

		for key, value := range headers {
			w.Header().Set(key, value)
		}
	}

	// Parse query string and add them as headers.
	query := r.URL.Query()
	for key, values := range query {
		for _, value := range values {
			slog.Info("Setting header", "key", key, "value", value)
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(code)
}

func (h *Handler) templateHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling template request", "url", r.URL.String())

	relativePath := strings.TrimPrefix(r.URL.Path, "/apps/")
	if relativePath == "" {
		relativePath = "index.html"
	}

	_, err := h.files.Open(relativePath)
	if err != nil {
		slog.Error("Error opening file", "error", err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	ext := filepath.Ext(relativePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	tmpl, err := template.ParseFS(h.files, relativePath)
	if err != nil {
		slog.Error("Error parsing template", "error", err)
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, relativePath, h.envContext)
	if err != nil {
		slog.Error("Error executing template", "error", err)
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

// serverSentEventHandler implements a long polling server that periodically sends "ping" messages.
func (h *Handler) serverSentEventHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling stream request", "url", r.URL.String())
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Write message to the client once every second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	counter := 0

	for {
		select {
		case <-ticker.C:
			timestamp := time.Now().Format(time.RFC3339)
			counter++
			message := fmt.Sprintf("data: { \"timestamp\": \"%s\", \"counter\": \"%d\" }\n\n", timestamp, counter)
			_, err := w.Write([]byte(message))
			if err != nil {
				slog.Error("Error writing to stream", "error", err)
				return
			}
			w.(http.Flusher).Flush()
			slog.Info("Sent message to client", "counter", counter)

		case <-ctx.Done():
			slog.Info("Client disconnected")
			return
		}
	}
}

func (h *Handler) webSocketHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling websocket request", "url", r.URL.String())

	if r.Header.Get("Upgrade") != "websocket" {
		slog.Warn("Invalid upgrade request")
		http.Error(w, "Invalid upgrade request", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Connection") != "Upgrade" {
		slog.Warn("Invalid connection header")
		http.Error(w, "Invalid connection header", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		slog.Warn("Invalid websocket version")
		http.Error(w, "Invalid websocket version", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Sec-WebSocket-Key") == "" {
		slog.Warn("Missing websocket key")
		http.Error(w, "Missing websocket key", http.StatusBadRequest)
		return
	}

	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", calculateWebSocketAcceptKey(r.Header.Get("Sec-WebSocket-Key")))
	w.WriteHeader(http.StatusSwitchingProtocols)

	ctx := r.Context()

	// Get the socket from the response writer.
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		slog.Error("Failed to hijack connection", "error", err)
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	slog.Info("WebSocket connection established")

	// Channel to signal client disconnection.
	disconnected := make(chan bool)

	// Detect client disconnection by (dummy) reading from the connection.
	go func() {
		defer close(disconnected)
		for {
			one := make([]byte, 1)
			_, err := conn.Read(one)
			if err == io.EOF {
				return
			}
		}
	}()

	// Write message to the client once every second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	counter := 0

	for {
		select {
		case <-ticker.C:
			timestamp := time.Now().Format(time.RFC3339)
			counter++
			payload := fmt.Sprintf("{ \"timestamp\": \"%s\", \"counter\": \"%d\" }", timestamp, counter)
			payloadLen := len(payload)

			frame := make([]byte, payloadLen+2)
			frame[0] = 0x81             // Text frame.
			frame[1] = byte(payloadLen) // Payload length.
			copy(frame[2:], payload)    // Payload data.

			_, err := buf.Write(frame)
			if err != nil {
				slog.Error("Error writing to websocket", "error", err)
				return
			}
			buf.Flush()
			slog.Info("Sent message to client", "counter", counter)

		case <-ctx.Done():
		case <-disconnected:
			slog.Info("Client disconnected")
			return
		}
	}
}

func calculateWebSocketAcceptKey(key string) string {
	// https://datatracker.ietf.org/doc/html/rfc6455#section-1.3
	buf := key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.New() //nolint:gosec
	hash.Write([]byte(buf))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
