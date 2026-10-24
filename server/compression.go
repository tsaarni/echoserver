package server

import (
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// encoder is a streaming compressor that supports flushing buffered data.
type encoder interface {
	io.WriteCloser
	Flush() error
}

// encoders maps supported content codings to encoder constructors using each library's default level.
var encoders = map[string]func(io.Writer) (encoder, error){
	"gzip": func(w io.Writer) (encoder, error) { return gzip.NewWriter(w), nil },
	"br":   func(w io.Writer) (encoder, error) { return brotli.NewWriter(w), nil },
	"zstd": func(w io.Writer) (encoder, error) {
		// Limit window size to 8MB for browser compatibility (RFC 9659) and avoid per-request goroutines.
		return zstd.NewWriter(w, zstd.WithWindowSize(8<<20), zstd.WithEncoderConcurrency(1))
	},
}

// acceptToken is a content coding from the Accept-Encoding header with its quality value.
type acceptToken struct {
	coding string
	q      float64
}

// parseAcceptEncoding parses Accept-Encoding header value (RFC 9110 section 12.5.3).
// Tokens with an invalid quality value are ignored.
func parseAcceptEncoding(header string) []acceptToken {
	var tokens []acceptToken
	for part := range strings.SplitSeq(header, ",") {
		coding, params, _ := strings.Cut(part, ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding == "" {
			continue
		}
		q, ok := 1.0, true
		for param := range strings.SplitSeq(params, ";") {
			name, value, _ := strings.Cut(param, "=")
			if !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || !(v >= 0 && v <= 1) {
				ok = false
				break
			}
			q = v
		}
		if ok {
			tokens = append(tokens, acceptToken{coding: coding, q: q})
		}
	}
	return tokens
}

// negotiate returns the offered coding with the highest quality value in accept.
// Ties are resolved by the order of offered. Returns empty string if none is acceptable.
func negotiate(offered []string, accept []acceptToken) string {
	selected, selectedQ := "", 0.0
	for _, coding := range offered {
		if q := acceptQuality(coding, accept); q > selectedQ {
			selected, selectedQ = coding, q
		}
	}
	return selected
}

// acceptQuality returns the quality value for coding, falling back to the wildcard "*".
func acceptQuality(coding string, accept []acceptToken) float64 {
	wildcard := 0.0
	for _, t := range accept {
		if t.coding == coding {
			return t.q
		}
		if t.coding == "*" {
			wildcard = t.q
		}
	}
	return wildcard
}

// compressOptions holds the response compression options parsed from query parameters.
type compressOptions struct {
	encodings   []string
	force       bool
	contentType string
}

// parseCompressOptions parses compress, compress-mode and content-type query parameters.
func parseCompressOptions(query url.Values) (compressOptions, error) {
	var opts compressOptions

	if values, ok := query["compress"]; ok {
		for coding := range strings.SplitSeq(strings.Join(values, ","), ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))
			if _, ok := encoders[coding]; !ok {
				return opts, fmt.Errorf("invalid compress value %q: supported values are gzip, br, zstd", coding)
			}
			opts.encodings = append(opts.encodings, coding)
		}
	}

	if query.Has("compress-mode") {
		switch mode := query.Get("compress-mode"); mode {
		case "negotiate":
		case "force":
			opts.force = true
		default:
			return opts, fmt.Errorf("invalid compress-mode value %q: supported values are negotiate, force", mode)
		}
		if len(opts.encodings) == 0 {
			return opts, fmt.Errorf("compress-mode requires compress")
		}
	}

	if query.Has("content-type") {
		opts.contentType = query.Get("content-type")
		if _, _, err := mime.ParseMediaType(opts.contentType); err != nil {
			return opts, fmt.Errorf("invalid content-type value %q: %w", opts.contentType, err)
		}
	}

	return opts, nil
}

// compressResponse wraps w according to the compression options in the request query.
// The returned function must be called after the handler has written the response.
// If no options are set, w is returned unchanged.
func compressResponse(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func(), error) {
	opts, err := parseCompressOptions(r.URL.Query())
	if err != nil {
		return w, func() {}, err
	}
	if len(opts.encodings) == 0 && opts.contentType == "" {
		return w, func() {}, nil
	}

	cw := &compressWriter{ResponseWriter: w, contentType: opts.contentType}
	if len(opts.encodings) > 0 {
		if opts.force {
			cw.encoding = opts.encodings[0]
		} else {
			// The response depends on Accept-Encoding even if it ends up uncompressed.
			w.Header().Add("Vary", "Accept-Encoding")
			accept := parseAcceptEncoding(strings.Join(r.Header.Values("Accept-Encoding"), ","))
			cw.encoding = negotiate(opts.encodings, accept)
		}
	}

	return cw, cw.close, nil
}

// compressWriter applies content type override and compresses the response body with the selected encoding.
type compressWriter struct {
	http.ResponseWriter
	encoding    string
	contentType string
	enc         encoder
	wroteHeader bool
}

func (cw *compressWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		cw.ResponseWriter.WriteHeader(code)
		return
	}
	cw.wroteHeader = true

	h := cw.Header()
	if cw.contentType != "" {
		h.Set("Content-Type", cw.contentType)
	}
	if cw.encoding != "" {
		enc, err := encoders[cw.encoding](cw.ResponseWriter)
		if err != nil {
			slog.Error("Error creating encoder", "encoding", cw.encoding, "error", err)
		} else {
			cw.enc = enc
			h.Set("Content-Encoding", cw.encoding)
			h.Del("Content-Length")
		}
	}

	cw.ResponseWriter.WriteHeader(code)
}

func (cw *compressWriter) Write(data []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.enc == nil {
		return cw.ResponseWriter.Write(data)
	}
	return cw.enc.Write(data)
}

func (cw *compressWriter) Flush() {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.enc != nil {
		if err := cw.enc.Flush(); err != nil {
			return
		}
	}
	if flusher, ok := cw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// close writes any remaining compressed data and the encoding trailer.
func (cw *compressWriter) close() {
	if cw.enc == nil {
		return
	}
	if err := cw.enc.Close(); err != nil {
		slog.Debug("Error closing encoder", "encoding", cw.encoding, "error", err)
	}
}
