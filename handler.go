package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
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
)

type Handler struct {
	files      fs.FS
	envContext map[string]string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/apps/health":
		h.HealthHandler(w, r)
	case strings.HasPrefix(r.URL.Path, "/apps/status/"):
		h.StatusHandler(w, r)
	case strings.HasPrefix(r.URL.Path, "/apps/"):
		h.TemplateHandler(w, r)
	default:
		h.EchoHandler(w, r)
	}
}

func (h *Handler) EchoHandler(w http.ResponseWriter, r *http.Request) {
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
		h.handleTLS(r, info)
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

func (h *Handler) handleTLS(r *http.Request, info map[string]any) {
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

func (h *Handler) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) StatusHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling status request", "url", r.URL.String())

	re := regexp.MustCompile(`^/apps/status/(\d\d\d)$`)
	match := re.FindStringSubmatch(r.RequestURI)
	if match == nil {
		slog.Warn("Error parsing status code /apps/status/{code}")
		http.Error(w, "Invalid status code provided for /apps/status/{code}", http.StatusBadRequest)
		return
	}
	code, _ := strconv.Atoi(match[1])

	var headers map[string]string
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&headers); err != nil && err != io.EOF {
			slog.Warn("Error decoding JSON body", "error", err)
			http.Error(w, "Error decoding JSON body", http.StatusBadRequest)
			return
		}
	}

	for key, value := range headers {
		w.Header().Set(key, value)
	}

	w.WriteHeader(code)
}

func (h *Handler) TemplateHandler(w http.ResponseWriter, r *http.Request) {
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
