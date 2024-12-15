package main

import (
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
	default:
		h.echoHandler(w, r)
	}
}

// echoHandler gathers information about the incoming request and returns it as a JSON response.
func (h *Handler) echoHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling echo request", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("Error reading body", "error", err)
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		info["body"] = string(body)
	}

	if r.TLS != nil {
		h.decodeTLSInfo(r, info)
	}

	authorization := r.Header.Get("Authorization")
	if authorization != "" {
		h.decodeAuthorizationInfo(authorization, info)
	}

	if h.envContext != nil {
		info["env"] = h.envContext
	}

	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		slog.Error("Error marshaling JSON", "error", err)
		http.Error(w, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(jsonData)
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
