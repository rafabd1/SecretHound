package detector

import (
	"regexp"
	"strings"

	"github.com/rafabd1/SecretHound/core/secret"
)

type FallbackDetector struct {
	criticalPatterns map[string]*regexp.Regexp
	initialized      bool
}

func NewFallbackDetector() *FallbackDetector {
	fd := &FallbackDetector{
		criticalPatterns: make(map[string]*regexp.Regexp),
		initialized:      false,
	}
	
	fd.initialize()
	
	return fd
}

func (fd *FallbackDetector) initialize() {
	if fd.initialized {
		return
	}
	
	criticalRegexes := map[string]string{
		"aws_key":        `AKIA[0-9A-Z]{16}`,
		"github_token":   `ghp_[0-9a-zA-Z]{36}`,
		"stripe_key":     `sk_live_[0-9a-zA-Z]{24,34}`,
		"jwt_token":      `eyJ[a-zA-Z0-9_\-\.]{10,500}`,
		"password":       `(?i)password[\s]*[=:]+[\s]*["']([^'"]{8,30})["']`,
	}
	
	for name, pattern := range criticalRegexes {
		re, err := regexp.Compile(pattern)
		if err == nil {
			fd.criticalPatterns[name] = re
		}
	}
	
	fd.initialized = true
}

/* 
   Detects secrets using only critical patterns when primary detection fails
*/
func (fd *FallbackDetector) DetectWithFallback(content, url string) []secret.Secret {
	var secrets []secret.Secret
	
	if !fd.initialized || len(fd.criticalPatterns) == 0 {
		fd.initialize()
	}
	
	for name, pattern := range fd.criticalPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			
			value := match[0]
			if len(match) > 1 && match[1] != "" {
				value = match[1]
			}
			
			if len(value) < 8 {
				continue
			}
			
			s := secret.NewSecret(
				name,
				value,
				extractBasicContext(content, value),
				url,
				0,
			)
			
			secrets = append(secrets, s)
		}
	}
	
	return secrets
}

/* 
   Extracts a simple context string surrounding the found secret
*/
func extractBasicContext(content, value string) string {
	idx := strings.Index(content, value)
	if idx == -1 {
		return ""
	}
	
	start := max(0, idx-30)
	end := min(len(content), idx+len(value)+30)
	
	return content[start:end]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
