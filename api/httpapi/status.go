package httpapi

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// StatusCodeWriter is a wrapper for http.ResponseWriter to capture the status code.
type StatusCodeWriter struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	Status         int
}

// NewStatusCodeWriter wraps a http.ResponseWriter.
func NewStatusCodeWriter(w http.ResponseWriter, r *http.Request) *StatusCodeWriter {
	return &StatusCodeWriter{
		ResponseWriter: w,
		Request:        r,
	}
}

// Header wraps the original Header method.
func (scw *StatusCodeWriter) Header() http.Header {
	return scw.ResponseWriter.Header()
}

// Write wraps the original Write method.
func (scw *StatusCodeWriter) Write(b []byte) (int, error) {
	if scw.Status == 0 {
		scw.Status = 200
	}

	return scw.ResponseWriter.Write(b)
}

// WriteHeader wraps the original WriteHeader method to extract information.
func (scw *StatusCodeWriter) WriteHeader(code int) {
	scw.Status = code
	scw.ResponseWriter.WriteHeader(code)
}

// Hijack wraps the original Hijack method, if available.
func (scw *StatusCodeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := scw.ResponseWriter.(http.Hijacker)
	if ok {
		c, b, err := hijacker.Hijack()
		if err != nil {
			return nil, nil, err
		}
		scw.Status = -1
		return c, b, nil
	}
	return nil, nil, errors.New("response does not implement http.Hijacker")
}

// Flush wraps the original Flush method, if available.
func (scw *StatusCodeWriter) Flush() {
	flusher, ok := scw.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}
