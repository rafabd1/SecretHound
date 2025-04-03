package utils

import (
	"fmt"
	"net/url"
	"strings"
)

/*
	Extracts the domain from a URL string
 */
func ExtractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}
	
	if parsedURL.Host == "" {
		return "", fmt.Errorf("no host in URL: %s", urlStr)
	}
	
	host := parsedURL.Host
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	
	return host, nil
}

func IsValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

func SanitizeURL(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}
	
	return parsedURL.String()
}

func IsValidJSURL(urlStr string) bool {
	if !IsValidURL(urlStr) {
		return false
	}
	
	return strings.HasSuffix(strings.ToLower(urlStr), ".js") || 
		   strings.Contains(strings.ToLower(urlStr), ".js?") ||
		   strings.Contains(strings.ToLower(urlStr), ".js&")
}

/*
	Determines if a URL likely points to a JavaScript file
	based on extension or directory patterns
 */
func IsJavaScriptFile(url string) bool {
	if strings.HasSuffix(strings.ToLower(url), ".js") {
		return true
	}
	
	if strings.Contains(url, ".js?") || strings.Contains(url, ".js&") {
		return true
	}
	
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

func EnforceJSExtension(urlStr string) string {
	if IsValidJSURL(urlStr) {
		return urlStr
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr + ".js"
	}
	
	if parsedURL.RawQuery != "" {
		base := strings.Split(urlStr, "?")[0]
		query := "?" + parsedURL.RawQuery
		return base + ".js" + query
	}
	
	return urlStr + ".js"
}
