package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	
	return s[:maxLength-3] + "..."
}

func SplitLines(s string) []string {
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"), "\n")
	
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			result = append(result, line)
		}
	}
	
	return result
}

func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func HasAnyPrefix(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func HasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

func ContainsAny(s string, substrings ...string) bool {
	for _, substring := range substrings {
		if strings.Contains(s, substring) {
			return true
		}
	}
	return false
}

func FormatByteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

/* 
 * Formats time duration into a human-readable string
 * including hours, minutes and seconds when applicable
 */
func FormatDuration(d Duration) string {
	if d.Seconds() < 60.0 {
		return fmt.Sprintf("%.2f seconds", d.Seconds())
	}
	
	if d.Minutes() < 60.0 {
		seconds := d.Seconds() - float64(int(d.Minutes())*60)
		return fmt.Sprintf("%d minutes %.2f seconds", int(d.Minutes()), seconds)
	}
	
	hours := int(d.Hours())
	minutes := int(d.Minutes()) - hours*60
	seconds := d.Seconds() - float64(hours*3600+minutes*60)
	return fmt.Sprintf("%d hours %d minutes %.2f seconds", hours, minutes, seconds)
}

func SplitCamelCase(s string) []string {
	var words []string
	var currentWord strings.Builder
	
	for i, char := range s {
		if i > 0 && unicode.IsUpper(char) {
			words = append(words, currentWord.String())
			currentWord.Reset()
		}
		currentWord.WriteRune(char)
	}
	
	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}
	
	return words
}

func ContainsIgnoreCase(s, substr string) bool {
	s, substr = strings.ToLower(s), strings.ToLower(substr)
	return strings.Contains(s, substr)
}
