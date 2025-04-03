package core

import (
	"regexp"
	"strings"

	"github.com/rafabd1/SecretHound/utils"
)

type SecretValidator struct {
	commonPaths     []string
	mimeTypes       []string
	contextPatterns map[string][]string
	exclusionRegexes map[string]*regexp.Regexp
}

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
	
	validator.exclusionRegexes["url"] = regexp.MustCompile(`https?://[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\./]+`)
	validator.exclusionRegexes["path"] = regexp.MustCompile(`(?:\.?/)?[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+`)
	validator.exclusionRegexes["mime"] = regexp.MustCompile(`[a-zA-Z]+/[a-zA-Z0-9_\-\.\+]+`)
	
	return validator
}

/* 
   Evaluates a potential secret against various exclusion criteria to determine if it's a valid secret or a false positive
*/
func (sv *SecretValidator) IsValidSecret(secretType, value, context string) bool {
	for _, path := range sv.commonPaths {
		if strings.Contains(value, path) {
			return false
		}
	}
	
	for _, mime := range sv.mimeTypes {
		if strings.Contains(value, mime) {
			return false
		}
	}
	
	if patterns, exists := sv.contextPatterns[secretType]; exists {
		for _, pattern := range patterns {
			if strings.Contains(context, pattern) {
				return false
			}
		}
	}
	
	for _, regex := range sv.exclusionRegexes {
		if regex.MatchString(value) {
			return false
		}
	}
	
	if utils.HasCommonCodePattern(value) {
		return false
	}
	
	if utils.IsLikelyFilePath(value) {
		return false
	}
	
	if utils.IsLikelyContentType(value) {
		return false
	}
	
	return true
}
