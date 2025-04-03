package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// ExtractDomain extracts the domain from a URL
func ExtractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}
	
	if parsedURL.Host == "" {
		return "", fmt.Errorf("no host in URL: %s", urlStr)
	}
	
	// Remove port number if present
	host := parsedURL.Host
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	
	return host, nil
}

// IsValidURL checks if a string is a valid URL
func IsValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	// Check if the URL has a scheme and host
	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

// SanitizeURL sanitizes a URL
func SanitizeURL(urlStr string) string {
	// Trim whitespace
	urlStr = strings.TrimSpace(urlStr)
	
	// Add scheme if missing
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	
	// Parse and normalize the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr // Return the original if we can't parse it
	}
	
	// Ensure the URL ends with a trailing slash if it's just a domain
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}
	
	return parsedURL.String()
}

// IsValidJSURL checks if a URL points to a JavaScript file
func IsValidJSURL(urlStr string) bool {
	if !IsValidURL(urlStr) {
		return false
	}
	
	// Check if the URL ends with .js
	return strings.HasSuffix(strings.ToLower(urlStr), ".js") || 
		   strings.Contains(strings.ToLower(urlStr), ".js?") ||
		   strings.Contains(strings.ToLower(urlStr), ".js&")
}

// IsJavaScriptFile checks if a URL is likely a JavaScript file
func IsJavaScriptFile(url string) bool {
	// Check if the URL ends with .js or contains .js in the query string
	if strings.HasSuffix(strings.ToLower(url), ".js") {
		return true
	}
	
	// Check for common query string patterns for JavaScript
	if strings.Contains(url, ".js?") || strings.Contains(url, ".js&") {
		return true
	}
	
	// Check for common JavaScript directory patterns
	jsPatterns := []string{
		"/js/", "/javascript/", "/scripts/", "/assets/js/", 
		"/dist/", "/bundle/", "/vendor/", "/lib/",
	}
	
	for _, pattern := range jsPatterns {
		if strings.Contains(strings.ToLower(url), pattern) {
			return true
		}
	}
	
	return false
}

// EnforceJSExtension adds .js extension to URL if not present
func EnforceJSExtension(urlStr string) string {
	if IsValidJSURL(urlStr) {
		return urlStr
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr + ".js" // Simple case
	}
	
	// If there's a query string, insert .js before it
	if parsedURL.RawQuery != "" {
		base := strings.Split(urlStr, "?")[0]
		query := "?" + parsedURL.RawQuery
		return base + ".js" + query
	}
	
	// Otherwise just append .js
	return urlStr + ".js"
}
