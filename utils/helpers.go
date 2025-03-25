package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
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

// ReadLinesFromFile reads lines from a file
func ReadLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	var lines []string
	scanner := bufio.NewScanner(file)
	
	// Increase buffer size for very long lines
	const maxCapacity = 512 * 1024 // 512KB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	
	return lines, nil
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
