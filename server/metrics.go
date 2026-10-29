package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc/stats"
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
func ConnStateMetrics(conn net.Conn, state http.ConnState) {
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
func MetricsMiddleware(next http.Handler) http.Handler {
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

func (rw *responseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// gRPC byte metrics. Labels match the go-grpc-middleware message counters.
var (
	grpcMsgReceivedBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_msg_received_bytes_total",
			Help: "Total number of gRPC message bytes received, including the 5-byte message header.",
		},
		[]string{"grpc_type", "grpc_service", "grpc_method"},
	)

	grpcMsgSentBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_msg_sent_bytes_total",
			Help: "Total number of gRPC message bytes sent, including the 5-byte message header.",
		},
		[]string{"grpc_type", "grpc_service", "grpc_method"},
	)
)

// grpcBytesStatsHandler counts gRPC message bytes as seen on the wire.
// Only complete messages are counted.
type grpcBytesStatsHandler struct{}

// grpcCallLabels is stored in the RPC context by TagRPC and completed by the Begin event.
type grpcCallLabels struct {
	typ, service, method string
}

type grpcCallLabelsKey struct{}

func (grpcBytesStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	service, method, ok := strings.Cut(strings.TrimPrefix(info.FullMethodName, "/"), "/")
	if !ok {
		service, method = "unknown", "unknown"
	}
	return context.WithValue(ctx, grpcCallLabelsKey{}, &grpcCallLabels{service: service, method: method})
}

func (grpcBytesStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	labels, ok := ctx.Value(grpcCallLabelsKey{}).(*grpcCallLabels)
	if !ok {
		return
	}
	switch s := s.(type) {
	case *stats.Begin:
		labels.typ = grpcType(s.IsClientStream, s.IsServerStream)
	case *stats.InPayload:
		grpcMsgReceivedBytes.WithLabelValues(labels.typ, labels.service, labels.method).Add(float64(s.WireLength))
	case *stats.OutPayload:
		grpcMsgSentBytes.WithLabelValues(labels.typ, labels.service, labels.method).Add(float64(s.WireLength))
	}
}

func (grpcBytesStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (grpcBytesStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

// grpcType returns the RPC type with the same values as go-grpc-middleware.
func grpcType(clientStream, serverStream bool) string {
	switch {
	case clientStream && serverStream:
		return "bidi_stream"
	case clientStream:
		return "client_stream"
	case serverStream:
		return "server_stream"
	default:
		return "unary"
	}
}
