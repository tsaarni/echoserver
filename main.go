package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

var envContext map[string]string

func echoHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling echo request", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)
	info := map[string]interface{}{
		"method":         r.Method,
		"url":            r.URL.String(),
		"proto":          r.Proto,
		"header":         r.Header,
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
		handleTLS(r, info)
	}

	if envContext != nil {
		info["env"] = envContext
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleTLS(r *http.Request, info map[string]interface{}) {
	slog.Info("TLS connection", "version", tls.VersionName(r.TLS.Version), "cipher_suite", tls.CipherSuiteName(r.TLS.CipherSuite))
	var clientCerts string
	for _, cert := range r.TLS.PeerCertificates {
		clientCerts += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	info["tls"] = map[string]interface{}{
		"version":                  tls.VersionName(r.TLS.Version),
		"alpn_negotiated_protocol": r.TLS.NegotiatedProtocol,
		"cipher_suite":             tls.CipherSuiteName(r.TLS.CipherSuite),
		"peer_certificates":        clientCerts,
	}
}

func parseEnvContext() {
	const prefix = "ENV_"
	env := map[string]string{}
	var envLog []any
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, prefix) {
			pair := strings.SplitN(e, "=", 2)
			env[pair[0]] = pair[1]
			envLog = append(envLog, pair[0], pair[1])
		}
	}
	if len(env) > 0 {
		envContext = env
		slog.Info("Environment context", envLog...)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling status request", "url", r.URL.String())
	code := http.StatusBadRequest

	re := regexp.MustCompile(`^/status/(\d\d\d)$`)
	match := re.FindStringSubmatch(r.RequestURI)
	if match != nil {
		code, _ = strconv.Atoi(match[1])
	}

	var headers map[string]string
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&headers); err != nil && err != io.EOF {
			slog.Error("Error decoding JSON body", "error", err)
			http.Error(w, "Error decoding JSON body", http.StatusBadRequest)
			return
		}
	}

	for key, value := range headers {
		w.Header().Set(key, value)
	}

	w.WriteHeader(code)
}

func main() {
	slog.Info("Starting server")

	parseEnvContext()

	http.HandleFunc("/", echoHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/status/", statusHandler)
	//fs := http.FileServer(http.Dir("./static"))
	//http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	portNumber := os.Getenv("PORT")
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile != "" && keyFile != "" {
		if portNumber == "" {
			portNumber = "8443"
		}

		server := &http.Server{
			Addr: ":" + portNumber,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequestClientCert,
			},
		}
		slog.Info("Server is running in HTTPS mode", "port", portNumber, "tls_cert_file", certFile, "tls_key_file", keyFile)
		err := server.ListenAndServeTLS(certFile, keyFile)
		if err != nil {
			slog.Error("Error starting HTTPS server", "error", err)
		}
	} else {
		if portNumber == "" {
			portNumber = "8080"
		}
		slog.Info("Server is running in HTTP mode", "port", portNumber)
		err := http.ListenAndServe(":"+portNumber, nil)
		if err != nil {
			slog.Error("Error starting HTTP server", "error", err)
		}
	}
}
