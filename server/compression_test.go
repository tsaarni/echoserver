package server

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAcceptEncoding(t *testing.T) {
	tests := []struct {
		header string
		want   []acceptToken
	}{
		{"", nil},
		{"gzip", []acceptToken{{"gzip", 1}}},
		{"gzip, br", []acceptToken{{"gzip", 1}, {"br", 1}}},
		{" GZIP ;Q=0.5 , Br;q=1.0", []acceptToken{{"gzip", 0.5}, {"br", 1}}},
		{"gzip;q=0", []acceptToken{{"gzip", 0}}},
		{"*;q=0.1, identity", []acceptToken{{"*", 0.1}, {"identity", 1}}},
		{"gzip;q=abc, br", []acceptToken{{"br", 1}}},
		{"gzip;q=2, br;q=-1, zstd;q=NaN", nil},
		{"gzip;foo=bar;q=0.3", []acceptToken{{"gzip", 0.3}}},
		{",,gzip,,", []acceptToken{{"gzip", 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			assert.Equal(t, tt.want, parseAcceptEncoding(tt.header))
		})
	}
}

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name    string
		offered []string
		accept  string
		want    string
	}{
		{"empty header", []string{"gzip"}, "", ""},
		{"server order wins on tie", []string{"br", "gzip"}, "gzip, br", "br"},
		{"server order wins on tie reversed", []string{"gzip", "br"}, "br, gzip", "gzip"},
		{"client quality wins", []string{"br", "gzip"}, "gzip, br;q=0.5", "gzip"},
		{"not offered", []string{"zstd"}, "gzip, br", ""},
		{"q=0 excludes", []string{"gzip", "br"}, "gzip;q=0, br;q=0.1", "br"},
		{"all q=0", []string{"gzip", "br"}, "gzip;q=0, br;q=0", ""},
		{"wildcard", []string{"zstd"}, "*", "zstd"},
		{"wildcard does not override explicit", []string{"gzip", "br"}, "gzip;q=0, *", "br"},
		{"wildcard q=0", []string{"gzip"}, "*;q=0", ""},
		{"identity ignored", []string{"gzip"}, "identity, gzip;q=0.1", "gzip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, negotiate(tt.offered, parseAcceptEncoding(tt.accept)))
		})
	}
}

// decode returns the decoded response body according to Content-Encoding.
func decode(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	var r io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		require.NoError(t, err)
		r = gr
	case "br":
		r = brotli.NewReader(resp.Body)
	case "zstd":
		zr, err := zstd.NewReader(resp.Body)
		require.NoError(t, err)
		defer zr.Close()
		r = zr
	case "":
	default:
		t.Fatalf("unexpected Content-Encoding %q", resp.Header.Get("Content-Encoding"))
	}
	body, err := io.ReadAll(r)
	require.NoError(t, err)
	return body
}

// request sends a request to HTTPHandler without transparent decompression.
func request(t *testing.T, method, url, acceptEncoding string) *http.Response {
	t.Helper()
	server := httptest.NewServer(NewHTTPHandler(nil, nil, nil))
	t.Cleanup(server.Close)

	req, err := http.NewRequest(method, server.URL+url, nil)
	require.NoError(t, err)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestCompressEcho(t *testing.T) {
	for _, encoding := range []string{"gzip", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			resp := request(t, "GET", "/foo?compress=gzip,br,zstd", encoding)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, encoding, resp.Header.Get("Content-Encoding"))
			assert.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			var info map[string]any
			require.NoError(t, json.Unmarshal(decode(t, resp), &info))
			assert.Equal(t, "/foo?compress=gzip,br,zstd", info["url"])
		})
	}
}

func TestCompressDownload(t *testing.T) {
	for _, encoding := range []string{"gzip", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			resp := request(t, "GET", "/download?bytes=100k&compress="+encoding, encoding)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, encoding, resp.Header.Get("Content-Encoding"))
			// The uncompressed length must not be sent; Go may set the compressed length for small responses.
			assert.NotEqual(t, "102400", resp.Header.Get("Content-Length"))
			assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))

			want, err := io.ReadAll(io.LimitReader(&patternByteReader{}, 100*1024))
			require.NoError(t, err)
			assert.Equal(t, want, decode(t, resp))
		})
	}
}

func TestCompressRepeatedParameter(t *testing.T) {
	resp := request(t, "GET", "/?compress=zstd&compress=gzip", "gzip")
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
}

func TestCompressNegotiateNotAccepted(t *testing.T) {
	for _, acceptEncoding := range []string{"", "br"} {
		t.Run(acceptEncoding, func(t *testing.T) {
			resp := request(t, "GET", "/download?bytes=100&compress=gzip", acceptEncoding)
			assert.Empty(t, resp.Header.Get("Content-Encoding"))
			assert.Equal(t, "Accept-Encoding", resp.Header.Get("Vary"))
			assert.Equal(t, "100", resp.Header.Get("Content-Length"))
			assert.Len(t, decode(t, resp), 100)
		})
	}
}

func TestCompressForce(t *testing.T) {
	resp := request(t, "GET", "/?compress=br,gzip&compress-mode=force", "gzip")
	assert.Equal(t, "br", resp.Header.Get("Content-Encoding"))
	assert.Empty(t, resp.Header.Get("Vary"))
	assert.NotEmpty(t, decode(t, resp))

	resp = request(t, "GET", "/?compress=zstd&compress-mode=force", "")
	assert.Equal(t, "zstd", resp.Header.Get("Content-Encoding"))
	assert.NotEmpty(t, decode(t, resp))
}

func TestCompressContentType(t *testing.T) {
	resp := request(t, "GET", "/download?bytes=10&content-type=text/plain", "gzip")
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
	assert.Empty(t, resp.Header.Get("Content-Encoding"))
	assert.Empty(t, resp.Header.Get("Vary"))
	assert.Len(t, decode(t, resp), 10)

	resp = request(t, "GET", "/?compress=gzip&content-type=text/csv%3B+charset%3Dutf-8", "gzip")
	assert.Equal(t, "text/csv; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	assert.NotEmpty(t, decode(t, resp))
}

func TestCompressHead(t *testing.T) {
	get := request(t, "GET", "/?compress=gzip", "gzip")
	head := request(t, "HEAD", "/?compress=gzip", "gzip")
	assert.Equal(t, http.StatusOK, head.StatusCode)
	assert.Equal(t, get.Header.Get("Content-Encoding"), head.Header.Get("Content-Encoding"))
	assert.Equal(t, get.Header.Get("Vary"), head.Header.Get("Vary"))
	assert.Equal(t, get.Header.Get("Content-Type"), head.Header.Get("Content-Type"))
}

func TestCompressInvalidOptions(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"/?compress=deflate", `invalid compress value "deflate"`},
		{"/?compress=gzip,lz4", `invalid compress value "lz4"`},
		{"/?compress=", `invalid compress value ""`},
		{"/download?compress=gzip&compress-mode=foo", `invalid compress-mode value "foo"`},
		{"/?compress-mode=force", "compress-mode requires compress"},
		{"/download?content-type=text%2F", `invalid content-type value "text/"`},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			resp := request(t, "GET", tt.url, "gzip")
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tt.want)
		})
	}
}

func TestCompressThrottledDownloadStreams(t *testing.T) {
	// 64 KB at 32 KB/s takes about two seconds; the first chunk must arrive well before that.
	start := time.Now()
	resp := request(t, "GET", "/download?bytes=64k&throttle=32k&compress=gzip", "gzip")
	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))

	gr, err := gzip.NewReader(bufio.NewReader(resp.Body))
	require.NoError(t, err)
	buf := make([]byte, 1)
	_, err = io.ReadFull(gr, buf)
	require.NoError(t, err)
	assert.Less(t, time.Since(start), time.Second)

	rest, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Len(t, rest, 64*1024-1)
}
