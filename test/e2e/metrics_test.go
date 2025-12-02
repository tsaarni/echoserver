//go:build e2e

package e2e

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/tsaarni/echoserver/server"
)

// Test MetricsMiddleware wrapper behavior by invoking it directly with a fake handler
func (s *E2ETestSuite) TestMetricsMiddlewareWrapper() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("hello"))
	})
	wrapped := server.MetricsMiddleware(handler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/test", strings.NewReader("hello"))
	s.Require().NoError(err)
	req.ContentLength = int64(len("hello"))
	wrapped.ServeHTTP(rr, req)
	s.Equal(http.StatusInternalServerError, rr.Code)
	s.Equal("hello", rr.Body.String())
}

// Test ConnStateMetrics function with different state transitions
func (s *E2ETestSuite) TestConnStateMetricsTransitions() {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Simulate connection states
	server.ConnStateMetrics(a, http.StateNew)
	server.ConnStateMetrics(a, http.StateActive)
	server.ConnStateMetrics(a, http.StateIdle)
	server.ConnStateMetrics(a, http.StateHijacked)
	server.ConnStateMetrics(a, http.StateClosed)
	// No explicit assertions; we simply ensure no panic and transitions run
	time.Sleep(10 * time.Millisecond)
}
