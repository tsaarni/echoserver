package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

// Start starts HTTP and HTTPS servers.
func Start(files fs.FS, envContext map[string]string, httpAddr, httpsAddr, certFile, keyFile, keyLogFile string) (func(), chan error, error) {
	handler := createMuxHandler(files, envContext)

	wrappedHandler := MetricsMiddleware(handler)

	httpServer := newHTTPServer(httpAddr, wrappedHandler)
	httpsServer, err := newHTTPSServer(httpsAddr, certFile, keyFile, keyLogFile, wrappedHandler)
	if err != nil {
		return nil, nil, err
	}

	errChannel := make(chan error, 1)

	// Start servers.
	if httpAddr != "" {
		go func() {
			slog.Info("Server is running in HTTP mode", "address", httpAddr)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP server error", "error", err)
				errChannel <- err
			}
		}()
	}

	if httpsServer != nil {
		go func() {
			slog.Info("Server is running in HTTPS mode", "address", httpsAddr,
				"tls_cert_file", certFile, "tls_key_file", keyFile)
			if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS server error", "error", err)
				errChannel <- err
			}
		}()
	}

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if httpServer != nil {
			_ = httpServer.Shutdown(ctx)
		}
		if httpsServer != nil {
			_ = httpsServer.Shutdown(ctx)
		}
	}

	return stop, errChannel, nil
}

func createMuxHandler(files fs.FS, envContext map[string]string) http.Handler {
	httpHandler := NewHTTPHandler(files, envContext)
	grpcService := NewGRPCEchoService(envContext)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		contentType, _, _ = mime.ParseMediaType(contentType)

		if strings.HasPrefix(contentType, "application/grpc") {
			grpcService.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: time.Duration(5) * time.Second,
		Protocols:         &protocols,
		ConnState:         ConnStateMetrics,
		Handler:           handler,
	}
}

func newHTTPSServer(addr, certFile, keyFile, keyLogFile string, handler http.Handler) (*http.Server, error) {
	var httpsServer *http.Server
	if certFile != "" && keyFile != "" {
		httpsServer = &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: time.Duration(5) * time.Second,
			ConnState:         ConnStateMetrics,
			Handler:           handler,
		}

		lookupCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				slog.Error("Error loading certificate", "error", err)
				return nil, err
			}
			return &cert, nil
		}

		// Call lookupCert once to check if the certificate and key files are valid.
		_, err := lookupCert(nil)
		if err != nil {
			return nil, err
		}

		var keyLogWriter io.Writer
		if keyLogFile != "" {
			keyLogWriter, err = os.OpenFile(keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				return nil, fmt.Errorf("error opening key log file: %w", err)
			}
			slog.Info("Enabling TLS master secret logging", "SSLKEYLOGFILE", keyLogFile)
		}

		httpsServer.TLSConfig = &tls.Config{ // #nosec // G402: TLS MinVersion too low.
			ClientAuth:     tls.RequestClientCert,
			GetCertificate: lookupCert,
			KeyLogWriter:   keyLogWriter,
		}
	}
	return httpsServer, nil
}
