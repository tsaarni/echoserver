package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultHTTPAddr  = ":8080"
	defaultHTTPSAddr = ":8443"
)

type Config struct {
	Live       bool
	HTTPAddr   string
	HTTPSAddr  string
	CertFile   string
	KeyFile    string
	KeyLogFile string
	LogLevel   string
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
	live := flag.Bool("live", false, "Serve live static files")
	httpAddr := flag.String("http-addr", "", "Address to bind the HTTP server socket")
	httpsAddr := flag.String("https-addr", "", "Address to bind the HTTPS server socket")
	certFile := flag.String("tls-cert-file", "", "Path to TLS certificate file")
	keyFile := flag.String("tls-key-file", "", "Path to TLS key file")
	logLevel := flag.String("log-level", "", "Log level (debug, info, warn, error, none)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		fmt.Fprintf(os.Stderr, "  HTTP_ADDR\n\tAddress to bind the HTTP server socket\n")
		fmt.Fprintf(os.Stderr, "  HTTPS_ADDR\n\tAddress to bind the HTTPS server socket\n")
		fmt.Fprintf(os.Stderr, "  TLS_CERT_FILE\n\tPath to TLS certificate file\n")
		fmt.Fprintf(os.Stderr, "  TLS_KEY_FILE\n\tPath to TLS key file\n")
		fmt.Fprintf(os.Stderr, "  ENV_*\n\tEnvironment variables to be used as context info in the echo response\n")
		fmt.Fprintf(os.Stderr, "  SSLKEYLOGFILE\n\tPath to write the TLS master secret log file\n")
	}

	flag.Parse()

	getEnv := func(key, flagValue, defaultValue string) string {
		if flagValue != "" {
			return flagValue
		}
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		return defaultValue
	}

	return &Config{
		Live:       *live,
		HTTPAddr:   getEnv("HTTP_ADDR", *httpAddr, defaultHTTPAddr),
		HTTPSAddr:  getEnv("HTTPS_ADDR", *httpsAddr, defaultHTTPSAddr),
		CertFile:   getEnv("TLS_CERT_FILE", *certFile, ""),
		KeyFile:    getEnv("TLS_KEY_FILE", *keyFile, ""),
		KeyLogFile: os.Getenv("SSLKEYLOGFILE"),
		LogLevel:   getEnv("LOG_LEVEL", *logLevel, "debug"),
	}
}

func parseLogLevel(level *string) slog.Level {
	if level == nil {
		return slog.LevelInfo
	}
	switch strings.ToLower(*level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "none":
		return slog.Level(999) // Higher than any defined level.
	default:
		slog.Warn("Unknown log level, defaulting to info", "log-level", *level)
		return slog.LevelInfo
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

func startHTTPServer(addr string) {
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
	}
	slog.Info("Server is running in HTTP mode", "address", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		slog.Error("Error starting HTTP server", "error", err)
	}
}

func startHTTPSServer(addr string, certFile, keyFile string, keyLogFile string) {
	lookupCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			slog.Error("Error loading certificate", "error", err)
			return nil, err
		}
		return &cert, nil
	}

	// Call lookupCert to check if the certificate and key files are valid.
	_, err := lookupCert(nil)
	if err != nil {
		os.Exit(1)
	}

	var keyLogWriter io.Writer
	if keyLogFile != "" {
		keyLogWriter, err = os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			slog.Error("Error opening key log file", "error", err)
			os.Exit(1)
		}
		slog.Info("Enabling TLS master secret logging", "SSLKEYLOGFILE", keyLogFile)
	}

	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
	}
	server.TLSConfig = &tls.Config{ // #nosec // G402: TLS MinVersion too low.
		ClientAuth:     tls.RequestClientCert,
		GetCertificate: lookupCert,
		KeyLogWriter:   keyLogWriter,
	}
	slog.Info("Server is running in HTTPS mode", "address", server.Addr,
		"tls_cert_file", certFile, "tls_key_file", keyFile)
	err = server.ListenAndServeTLS("", "")
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

	slog.SetLogLoggerLevel(parseLogLevel(&config.LogLevel))

	setupFilesystem(config.Live)
	parseEnvContext()

	handler := &Handler{
		files:      files,
		envContext: envContext,
	}

	http.Handle("/", metricsMiddleware(handler))

	if config.CertFile != "" && config.KeyFile != "" {
		go startHTTPSServer(config.HTTPSAddr, config.CertFile, config.KeyFile, config.KeyLogFile)
	}

	go startHTTPServer(config.HTTPAddr)

	select {}
}
