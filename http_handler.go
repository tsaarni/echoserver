package main

import (
	"bytes"
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
	"sync/atomic"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// patternByteReader implements io.Reader, returning a repeating pattern of bytes 0..255.
type patternByteReader struct{ pos int }

func (r *patternByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r.pos % 256)
		r.pos++
	}
	return len(p), nil
}

type HTTPHandler struct {
	files      fs.FS
	envContext map[string]string
}

// statusCode holds the persisted HTTP status code for /status responses.
var statusCode int32 = http.StatusOK

func newHTTPHandler(files fs.FS, envContext map[string]string) *HTTPHandler {
	return &HTTPHandler{
		files:      files,
		envContext: envContext,
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/status"):
		h.statusHandler(w, r)
	case strings.HasPrefix(r.URL.Path, "/apps/"):
		h.templateHandler(w, r)
	case r.URL.Path == "/sse":
		h.serverSentEventHandler(w, r)
	case r.URL.Path == "/websocket":
		h.webSocketHandler(w, r)
	case r.URL.Path == "/download":
		h.downloadHandler(w, r)
	case r.URL.Path == "/upload":
		h.uploadHandler(w, r)
	case r.URL.Path == "/metrics":
		promhttp.Handler().ServeHTTP(w, r)
	default:
		h.echoHandler(w, r)
	}
}

// echoHandler gathers information about the incoming request and returns it as a JSON response.
func (h *HTTPHandler) echoHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling echo request", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")

	jsonData, err := h.createEchoResponseBody(r)
	if err != nil {
		http.Error(w, "Error while processing request", http.StatusBadRequest)
		return
	}

	_, _ = w.Write(jsonData)
}

func (h *HTTPHandler) createEchoResponseBody(r *http.Request) ([]byte, error) {
	info := h.collectRequestInfo(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		info["body"] = string(body)
	}

	h.processRequestBody(r, body, info)

	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func (h *HTTPHandler) collectRequestInfo(r *http.Request) map[string]any {
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

func (h *HTTPHandler) processRequestBody(r *http.Request, body []byte, info map[string]any) {
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err == nil {
			info["form"] = values
		}
	}
}

// decodeTLSInfo extracts TLS information from the request.
func (h *HTTPHandler) decodeTLSInfo(r *http.Request, info map[string]any) {
	var clientCerts string
	var clientCertDecoded []map[string]any
	for _, cert := range r.TLS.PeerCertificates {
		clientCerts += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		clientCertDecoded = append(clientCertDecoded, map[string]any{
			"subject":       cert.Subject.String(),
			"issuer":        cert.Issuer.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before":    cert.NotBefore,
			"not_after":     cert.NotAfter,
		})
	}

	if len(clientCertDecoded) > 0 {
		slog.Debug("TLS info", "version", tls.VersionName(r.TLS.Version), "cipher_suite", tls.CipherSuiteName(r.TLS.CipherSuite), "peer_certificate_subject", r.TLS.PeerCertificates[0].Subject.String(), "peer_certificate_not_before", r.TLS.PeerCertificates[0].NotBefore, "peer_certificate_not_after", r.TLS.PeerCertificates[0].NotAfter, "peer_certificate_serial_number", r.TLS.PeerCertificates[0].SerialNumber.String())
	} else {
		slog.Debug("TLS info", "version", tls.VersionName(r.TLS.Version), "cipher_suite", tls.CipherSuiteName(r.TLS.CipherSuite))
	}

	info["tls"] = map[string]any{
		"version":                   tls.VersionName(r.TLS.Version),
		"alpn_negotiated_protocol":  r.TLS.NegotiatedProtocol,
		"cipher_suite":              tls.CipherSuiteName(r.TLS.CipherSuite),
		"peer_certificates":         clientCerts,
		"peer_certificates_decoded": clientCertDecoded,
	}
}

// decodeAuthorizationInfo extracts information from the Authorization header.
func (h *HTTPHandler) decodeAuthorizationInfo(authorization string, info map[string]any) {
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

// statusHandler handles requests to the /status endpoint.
// If the path is /status, it returns the currently stored status code (default is 200 OK).
// If a `set` query parameter is provided, it updates the stored status code.
// For paths like /status/{code}, it responds with the specified status code.
func (h *HTTPHandler) statusHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling status request", "url", r.URL.String())

	var returnCode int64

	// If path is exactly /status, return the currently persisted status.
	if r.URL.Path == "/status" {
		// Update the stored status code.
		if v := r.URL.Query().Get("set"); v != "" {
			newCode, err := strconv.ParseInt(v, 10, 32)
			if err == nil && newCode >= 100 && newCode <= 599 {
				atomic.StoreInt32(&statusCode, int32(newCode))
				slog.Debug("Persisted status code", "code", newCode)
			} else {
				slog.Warn("Invalid status code provided for set parameter", "value", v, "error", err)
				http.Error(w, "Invalid status code provided for set parameter. Code must be a 3-digit number between 100 and 599.",
					http.StatusBadRequest)
				return
			}
		}
		returnCode = int64(atomic.LoadInt32(&statusCode))
	} else {

		// Respond with the status code extracted from the URL path.
		re := regexp.MustCompile(`^/status/(\d\d\d)$`)
		match := re.FindStringSubmatch(r.URL.Path)
		if match == nil {
			slog.Warn("Error parsing status code /status/{code}")
			http.Error(w, "Invalid status code provided for /status/{code}. Code must be a 3-digit number.",
				http.StatusBadRequest)
			return
		}
		returnCode, _ = strconv.ParseInt(match[1], 10, 32)

		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				slog.Warn("Error reading body", "error", err)
				http.Error(w, "Error reading body", http.StatusBadRequest)
				return
			}

			if len(bodyBytes) > 0 {
				var headers map[string]string
				if err := json.Unmarshal(bodyBytes, &headers); err == nil {
					for key, value := range headers {
						w.Header().Set(key, value)
					}
				}
			}

			// Restore the body for further processing.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Parse query string and add them as headers.
		query := r.URL.Query()
		for key, values := range query {
			for _, value := range values {
				slog.Debug("Setting header", "key", key, "value", value)
				w.Header().Add(key, value)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(int(returnCode))

	jsonData, err := h.createEchoResponseBody(r)
	if err != nil {
		http.Error(w, "Error while processing request", http.StatusBadRequest)
		return
	}

	_, _ = w.Write(jsonData)
}

func (h *HTTPHandler) templateHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling template request", "url", r.URL.String())

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
func (h *HTTPHandler) serverSentEventHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling stream request", "url", r.URL.String())
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
			slog.Debug("Sent message to client", "counter", counter)

		case <-ctx.Done():
			slog.Debug("Client disconnected")
			return
		}
	}
}

func (h *HTTPHandler) webSocketHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling websocket request", "url", r.URL.String())

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

	slog.Debug("WebSocket connection established")

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
			slog.Debug("Sent message to client", "counter", counter)

		case <-ctx.Done():
		case <-disconnected:
			slog.Debug("Client disconnected")
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

func (h *HTTPHandler) downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	downloadBytes := int64(1024 * 1024) // Default file size of 1MB unless overridden by query parameter.
	if size := r.URL.Query().Get("bytes"); size != "" {
		parsedSize, err := parseUnit(size)
		if err == nil {
			downloadBytes = parsedSize
		}
	}

	throttleStr := r.URL.Query().Get("throttle")
	throttle, err := parseUnit(throttleStr)
	if err != nil {
		http.Error(w, "Invalid throttle parameter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(downloadBytes, 10))

	slog.Debug("Handling download request", "url", r.URL.String(), "bytes", downloadBytes, "throttle", throttle)

	patternReader := io.LimitReader(&patternByteReader{}, downloadBytes)
	_, err = throttledCopy(w, patternReader, downloadBytes, throttle)
	if err != nil {
		slog.Error("Error writing download data", "error", err)
		return
	}

	slog.Debug("File download completed", "bytes", downloadBytes)
}

func (h *HTTPHandler) uploadHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Handling upload request", "url", r.URL.String())

	throttleStr := r.URL.Query().Get("throttle")
	throttle, err := parseUnit(throttleStr)
	if err != nil {
		http.Error(w, "Invalid throttle parameter", http.StatusBadRequest)
		return
	}

	bytesRead, err := throttledCopy(io.Discard, r.Body, 0, throttle)
	if err != nil {
		slog.Error("Error reading upload data", "error", err)
		http.Error(w, "Error reading upload data", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"bytes_uploaded": bytesRead,
	}

	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		slog.Error("Error marshaling JSON", "error", err)
		http.Error(w, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(jsonResp)
	slog.Debug("File upload completed", "bytes_uploaded", bytesRead)
}

// parseUnit parses query parameter supporting optional k/m/g suffixes.
func parseUnit(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	multiplier := int64(1)
	if strings.HasSuffix(s, "k") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "k")
	} else if strings.HasSuffix(s, "m") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "m")
	} else if strings.HasSuffix(s, "g") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "g")
	}
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return val * multiplier, nil
}

// throttledCopy copies data from src to dst, limiting the rate to throttle bytes/sec if throttle > 0.
func throttledCopy(dst io.Writer, src io.Reader, total int64, throttle int64) (written int64, err error) {
	const chunkSize = 4096
	buf := make([]byte, chunkSize)
	var copied int64
	start := time.Now()
	for total == 0 || copied < total {
		toRead := chunkSize
		if total > 0 && total-copied < int64(chunkSize) {
			toRead = int(total - copied)
		}
		n, readErr := src.Read(buf[:toRead])
		if n > 0 {
			wn, writeErr := dst.Write(buf[:n])
			copied += int64(wn)
			if writeErr != nil {
				return copied, writeErr
			}
			if throttle > 0 {
				elapsed := time.Since(start)
				expected := time.Duration(copied) * time.Second / time.Duration(throttle)
				if expected > elapsed {
					time.Sleep(expected - elapsed)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return copied, readErr
		}
	}
	return copied, nil
}
