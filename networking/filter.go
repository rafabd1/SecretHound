package networking

import (
	"net"
	"net/http"
	"strings"
)

// ResponseFilter filters HTTP responses
type ResponseFilter struct {
	contentTypeWhitelist []string
}

// NewResponseFilter creates a new response filter
func NewResponseFilter() *ResponseFilter {
	return &ResponseFilter{
		contentTypeWhitelist: []string{
			"application/javascript",
			"text/javascript",
			"application/x-javascript",
			"text/plain",
			"text/html", // Sometimes JS is embedded in HTML
			"application/json", // Sometimes JS is in JSON responses
		},
	}
}

// ShouldProcess determines if a response should be processed
func (rf *ResponseFilter) ShouldProcess(resp *http.Response) bool {
	// Check for successful status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Non-successful status code
		return false
	}

	// Check content type if present
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		// Check against whitelist
		for _, allowedType := range rf.contentTypeWhitelist {
			if strings.Contains(strings.ToLower(contentType), allowedType) {
				return true
			}
		}
		
		// If content type is present but not in whitelist, skip
		// However, some servers don't set content type correctly for JS files
		// So we also check the URL
		if strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), ".js") {
			return true
		}
		
		return false
	}
	
	// If no content type, accept if URL ends with .js
	if strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), ".js") {
		return true
	}
	
	// Default to true if we can't determine
	return true
}

// IsRateLimited checks if a response indicates rate limiting
func (rf *ResponseFilter) IsRateLimited(resp *http.Response) bool {
	// Check status code
	if resp.StatusCode == 429 {
		return true
	}
	
	// Check headers
	rateLimitHeaders := []string{
		"X-RateLimit-Remaining",
		"X-Rate-Limit-Remaining",
		"Retry-After",
	}
	
	for _, header := range rateLimitHeaders {
		if val := resp.Header.Get(header); val != "" {
			// If rate limit remaining is 0 or retry-after is present
			if val == "0" || (header == "Retry-After" && val != "") {
				return true
			}
		}
	}
	
	// Check for common rate limit messages in the response body
	rateLimitKeywords := []string{
		"rate limit exceeded",
		"too many requests",
		"rate limiting",
		"throttled",
	}
	
	// If the status code is in the 4xx range, it might be rate limiting with custom message
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		for _, keyword := range rateLimitKeywords {
			if strings.Contains(strings.ToLower(resp.Status), keyword) {
				return true
			}
		}
	}
	
	return false
}

// IsWAFBlocked checks if a response indicates WAF blocking
func (rf *ResponseFilter) IsWAFBlocked(resp *http.Response) bool {
	// Check status code (403 Forbidden often indicates WAF)
	if resp.StatusCode == 403 {
		// Additional check for WAF specific headers
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
		
		// Check for common WAF block messages
		wafKeywords := []string{
			"blocked",
			"firewall",
			"waf",
			"security",
			"suspicious",
			"violation",
			"challenge",
		}
		
		// If status is 403 and contains WAF keywords, it's likely a WAF block
		for _, keyword := range wafKeywords {
			if strings.Contains(strings.ToLower(resp.Status), keyword) {
				return true
			}
		}
	}
	
	// Check for specific WAF-like response codes
	wafStatusCodes := []int{418, 419, 420}
	for _, code := range wafStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}
	
	return false
}

// IsTimeout checks if an error represents a timeout
func (f *ResponseFilter) IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	
	// Check common timeout error patterns
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	
	// Check error string for timeout indicators
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

// AddContentTypeWhitelist adds a content type to the whitelist
func (rf *ResponseFilter) AddContentTypeWhitelist(contentType string) {
	rf.contentTypeWhitelist = append(rf.contentTypeWhitelist, strings.ToLower(contentType))
}
