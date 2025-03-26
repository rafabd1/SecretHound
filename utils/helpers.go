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

// IsJavaScriptFile verifica se um URL é para um arquivo JavaScript
func IsJavaScriptFile(url string) bool {
	// Verificar extensão
	if strings.HasSuffix(strings.ToLower(url), ".js") {
		return true
	}
	
	// Verificar parâmetros que indicam JavaScript
	if strings.Contains(url, ".js?") || strings.Contains(url, ".js&") {
		return true
	}
	
	// Verificar caminhos comuns para JavaScript
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

// IsMinfiedJavaScript verifica se o conteúdo é JavaScript minificado
func IsMinifiedJavaScript(content string) bool {
	// JavaScript minificado geralmente tem linhas muito longas
	lines := strings.Split(content, "\n")
	if len(lines) == 1 && len(content) > 1000 {
		return true
	}
	
	// Verificar densidade de ponto e vírgula e chaves
	semicolons := strings.Count(content, ";")
	braces := strings.Count(content, "{") + strings.Count(content, "}")
	
	// JavaScript minificado tem alta densidade de símbolos
	symbolDensity := float64(semicolons+braces) / float64(len(content))
	
	return symbolDensity > 0.02 // 2% threshold
}

// Helper function to check if string is likely Base64
func IsLikelyBase64(s string) bool {
    // Base64 uses characters A-Z, a-z, 0-9, +, /, and = for padding
    for _, c := range s {
        if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            return false
        }
    }
    
    // Check if length is valid for Base64 (multiple of 4 or close with padding)
    padding := 0
    if len(s) % 4 != 0 {
        padding = 4 - (len(s) % 4)
    }
    
    return (len(s) + padding) % 4 == 0
}

// Check if a string is a common English word
func IsCommonWord(s string) bool {
    commonWords := []string{
        "language", "location", "error", "fails", "request", "config", 
        "settings", "options", "parameters", "configuration", "context",
        "feature", "function", "values", "method", "result", "response",
    }
    
    s = strings.ToLower(s)
    for _, word := range commonWords {
        if s == word {
            return true
        }
    }
    
    return false
}
