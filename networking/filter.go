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
	
	return strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), ".js") || true
}

/* 
   Checks if a response indicates rate limiting based on status code and headers
*/
func (rf *ResponseFilter) IsRateLimited(resp *http.Response) bool {
	if resp.StatusCode == 429 {
		return true
	}
	
	rateLimitHeaders := []string{
		"X-RateLimit-Remaining",
		"X-Rate-Limit-Remaining",
		"Retry-After",
	}
	
	for _, header := range rateLimitHeaders {
		if val := resp.Header.Get(header); val != "" {
			if val == "0" || (header == "Retry-After" && val != "") {
				return true
			}
		}
	}
	
	rateLimitKeywords := []string{
		"rate limit exceeded",
		"too many requests",
		"rate limiting",
		"throttled",
	}
	
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		for _, keyword := range rateLimitKeywords {
			if strings.Contains(strings.ToLower(resp.Status), keyword) {
				return true
			}
		}
	}
	
	return false
}

/* 
   Checks if a response indicates Web Application Firewall blocking
*/
func (rf *ResponseFilter) IsWAFBlocked(resp *http.Response) bool {
	if resp.StatusCode == 403 {
		wafHeaders := []string{
			"X-Firewall-Block",
			"X-Aws-Waf",
			"X-Cloudflare-",
			"X-Sucuri-",
			"X-Akamai-",
			"X-CDN-",
			"X-Varnish",
		}
		
		for _, header := range wafHeaders {
			for key := range resp.Header {
				if strings.HasPrefix(strings.ToLower(key), strings.ToLower(header)) {
					return true
				}
			}
		}
		
		wafKeywords := []string{
			"blocked",
			"firewall",
			"waf",
			"security",
			"suspicious",
			"violation",
			"challenge",
		}
		
		for _, keyword := range wafKeywords {
			if strings.Contains(strings.ToLower(resp.Status), keyword) {
				return true
			}
		}
	}
	
	wafStatusCodes := []int{418, 419, 420}
	for _, code := range wafStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}
	
	return false
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
