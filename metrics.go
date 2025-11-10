package main

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP Request Metrics.
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests received.",
		},
		[]string{"method", "status_code"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	httpConcurrentRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_concurrent_requests",
			Help: "Current number of concurrent HTTP requests being handled.",
		},
	)

	httpConnectionsByState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "http_connections_by_state",
			Help: "Current number of connections in each state (new, active, idle, hijacked).",
		},
		[]string{"state"},
	)

	httpResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "Size of HTTP responses in bytes.",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method"},
	)

	httpRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "Size of HTTP requests in bytes.",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method"},
	)

	httpErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total number of HTTP errors encountered.",
		},
		[]string{"method", "status_code"},
	)

	// Server Uptime Metric.
	_ = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "server_uptime_seconds",
			Help: "Total uptime of the server in seconds.",
		},
		func() float64 {
			return time.Since(serverStartTime).Seconds()
		},
	)
	serverStartTime = time.Now()

	// Connection state tracking.
	connStateMu    sync.Mutex
	connStateTrack = make(map[net.Conn]http.ConnState)
)

// connStateMetrics tracks connection state changes for metrics.
func connStateMetrics(conn net.Conn, state http.ConnState) {
	connStateMu.Lock()
	defer connStateMu.Unlock()

	if prevState, exists := connStateTrack[conn]; exists {
		// Decrement the previous state counter.
		httpConnectionsByState.WithLabelValues(prevState.String()).Dec()
	}

	// Terminal states don't get incremented (connection is gone).
	if state == http.StateClosed {
		delete(connStateTrack, conn)
	} else {
		// Increment the new state counter and track it.
		httpConnectionsByState.WithLabelValues(state.String()).Inc()
		connStateTrack[conn] = state
	}

	// StateHijacked is terminal and outside server control.
	if state == http.StateHijacked {
		delete(connStateTrack, conn)
	}
}

// metricsMiddleware records metrics for HTTP requests.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		method := r.Method

		httpConcurrentRequests.Inc()
		defer httpConcurrentRequests.Dec()

		// Wrap response writer to capture status code and response size.
		ww := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r)

		httpRequestsTotal.WithLabelValues(method, strconv.Itoa(ww.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(method).Observe(time.Since(start).Seconds())
		httpResponseSize.WithLabelValues(method).Observe(float64(ww.bytesWritten))

		if r.ContentLength > 0 {
			httpRequestSize.WithLabelValues(method).Observe(float64(r.ContentLength))
		}

		if ww.statusCode >= 400 {
			httpErrorsTotal.WithLabelValues(method, strconv.Itoa(ww.statusCode)).Inc()
		}
	})
}

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriterWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriterWrapper) Write(data []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(data)
	rw.bytesWritten += n
	return n, err
}

func (rw *responseWriterWrapper) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
