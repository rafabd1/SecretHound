package core

import (
	"regexp"
	"strings"

	"github.com/rafabd1/SecretHound/utils"
)

// SecretValidator provides advanced validation for potential secrets
type SecretValidator struct {
	commonPaths     []string
	mimeTypes       []string
	contextPatterns map[string][]string
	exclusionRegexes map[string]*regexp.Regexp
}

// NewSecretValidator creates a new validator for secrets
func NewSecretValidator() *SecretValidator {
	validator := &SecretValidator{
		commonPaths: []string{
			"node_modules/", "/modules/", "/dist/", "/src/",
			"/documentation", "/docs/", "/examples/",
			"plugins/", "components/", "assets/",
		},
		
		mimeTypes: []string{
			"application/json", "application/xml", 
			"application/javascript", "application/x-www-form-urlencoded",
			"text/html", "text/plain", "text/css",
			"multipart/form-data",
		},
		
		contextPatterns: map[string][]string{
			"high_entropy_string": {
				"contentType", "Content-Type", "charset",
				"node_modules", "documentation", "plugins",
				"http://", "https://", ".html", ".js", ".css",
			},
			"jwt_token": {
				"example", "sample", "documentation",
			},
		},
		
		exclusionRegexes: make(map[string]*regexp.Regexp),
	}
	
	// Compile common exclusion regexes
	validator.exclusionRegexes["url"] = regexp.MustCompile(`https?://[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\./]+`)
	validator.exclusionRegexes["path"] = regexp.MustCompile(`(?:\.?/)?[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+`)
	validator.exclusionRegexes["mime"] = regexp.MustCompile(`[a-zA-Z]+/[a-zA-Z0-9_\-\.\+]+`)
	
	return validator
}

// IsValidSecret performs enhanced validation on a potential secret
func (sv *SecretValidator) IsValidSecret(secretType, value, context string) bool {
	// Skip common file paths and import paths
	for _, path := range sv.commonPaths {
		if strings.Contains(value, path) {
			return false
		}
	}
	
	// Skip MIME types
	for _, mime := range sv.mimeTypes {
		if strings.Contains(value, mime) {
			return false
		}
	}
	
	// Check specific patterns based on secret type
	if patterns, exists := sv.contextPatterns[secretType]; exists {
		for _, pattern := range patterns {
			if strings.Contains(context, pattern) {
				return false
			}
		}
	}
	
	// Apply regex-based exclusions
	for _, regex := range sv.exclusionRegexes {
		if regex.MatchString(value) {
			return false
		}
	}
	
	// Check for common code patterns that indicate non-secrets
	if utils.HasCommonCodePattern(value) {
		return false
	}
	
	// Check if this looks like a file path
	if utils.IsLikelyFilePath(value) {
		return false
	}
	
	// Check if this looks like a content type
	if utils.IsLikelyContentType(value) {
		return false
	}
	
	// By default, consider it a valid secret if no exclusion conditions matched
	return true
}
