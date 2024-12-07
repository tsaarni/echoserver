package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultHTTPPort  = "8080"
	defaultHTTPSPort = "8443"
)

type Config struct {
	Live      bool
	HTTPPort  string
	HTTPSPort string
	CertFile  string
	KeyFile   string
}

var (
	//go:embed apps/*
	staticFiles embed.FS

	// File system object to serve either live files from parsedStaticFiles or embedded files.
	files fs.FS

	// Environment variables used as context info in the echo response.
	envContext map[string]string
)

func newConfig() *Config {
	flag.Bool("live", false, "Serve live static files")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		fmt.Fprintf(os.Stderr, "  HTTP_PORT\n\tPort for HTTP server\n")
		fmt.Fprintf(os.Stderr, "  HTTPS_PORT\n\tPort for HTTPS server\n")
		fmt.Fprintf(os.Stderr, "  TLS_CERT_FILE\n\tPath to TLS certificate file\n")
		fmt.Fprintf(os.Stderr, "  TLS_KEY_FILE\n\tPath to TLS key file\n")
		fmt.Fprintf(os.Stderr, "  ENV_*\n\tEnvironment variables to be used as context info in the echo response\n")
	}
	flag.Parse()

	return &Config{
		Live:      flag.Lookup("live").Value.String() == "true",
		HTTPPort:  os.Getenv("HTTP_PORT"),
		HTTPSPort: os.Getenv("HTTPS_PORT"),
		CertFile:  os.Getenv("TLS_CERT_FILE"),
		KeyFile:   os.Getenv("TLS_KEY_FILE"),
	}
}

func setupFilesystem(live bool) {
	if live {
		slog.Info("Serving live static files")
		files = os.DirFS("./apps")
	} else {
		slog.Info("Serving embedded static files")
		files, _ = fs.Sub(staticFiles, "apps")
	}
}

func newHTTPServer(port, defaultPort string) *http.Server {
	if port == "" {
		port = defaultPort
	}
	return &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
	}
}

func startHTTPServer(port string) {
	server := newHTTPServer(port, defaultHTTPPort)
	slog.Info("Server is running in HTTP mode", "address", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("Error starting HTTP server", "error", err)
	}
}

func startHTTPSServer(port string, certFile, keyFile string) {
	lookupCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			slog.Error("Error loading certificate", "error", err)
			return nil, err
		}
		return &cert, nil
	}

	server := newHTTPServer(port, defaultHTTPSPort)
	server.TLSConfig = &tls.Config{ // #nosec // G402: TLS MinVersion too low.
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: lookupCert,
	}
	slog.Info("Server is running in HTTPS mode", "address", server.Addr,
		"tls_cert_file", certFile, "tls_key_file", keyFile)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		slog.Error("Error starting HTTPS server", "error", err)
	}
}

// parseEnvContext reads environment variables that start with "ENV_" and stores them to be used
// as context info in the echo response.
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

func main() {
	config := newConfig()

	setupFilesystem(config.Live)
	parseEnvContext()

	handler := &Handler{
		files:      files,
		envContext: envContext,
	}

	http.Handle("/", handler)

	if config.CertFile != "" && config.KeyFile != "" {
		go startHTTPSServer(config.HTTPSPort, config.CertFile, config.KeyFile)
	}

	go startHTTPServer(config.HTTPPort)

	select {}
}
