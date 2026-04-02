package networking

import (
	"net"
	"net/http"
	"strings"
)

type ResponseFilter struct {
	contentTypeWhitelist []string
}

func NewResponseFilter() *ResponseFilter {
	return &ResponseFilter{
		contentTypeWhitelist: []string{
			"application/javascript",
			"text/javascript",
			"application/x-javascript",
			"text/plain",
			"text/html",
			"application/json",
		},
	}
}

/*
Determines if an HTTP response should be processed based on status code and content type
*/
func (rf *ResponseFilter) ShouldProcess(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		for _, allowedType := range rf.contentTypeWhitelist {
			if strings.Contains(strings.ToLower(contentType), allowedType) {
				return true
			}
		}

		return strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), ".js")
	}

	return true
}

/*
Checks if a response indicates rate limiting based on status code and headers
*/
func (rf *ResponseFilter) IsRateLimited(resp *http.Response) bool {
	// Strict mode: only explicit HTTP 429 is considered rate limiting.
	return resp.StatusCode == 429
}

/*
Determines if an error represents a network timeout
*/
func (f *ResponseFilter) IsTimeout(err error) bool {
	if err == nil {
		return false
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	errStr := err.Error()
	timeoutPatterns := []string{
		"timeout",
		"timed out",
		"deadline exceeded",
		"context deadline exceeded",
		"i/o timeout",
		"TLS handshake timeout",
		"operation timed out",
	}

	for _, pattern := range timeoutPatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

func (rf *ResponseFilter) AddContentTypeWhitelist(contentType string) {
	rf.contentTypeWhitelist = append(rf.contentTypeWhitelist, strings.ToLower(contentType))
}
