package core

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/rafabd1/SecretHound/utils"
)

// RegexManager handles loading and applying regex patterns
type RegexManager struct {
    patterns           map[string]*regexp.Regexp
    exclusionPatterns  []*regexp.Regexp       // Patterns to filter false positives
    patternExclusions  map[string][]*regexp.Regexp // Specific exclusions per pattern
    excludedExtensions []string               // File extensions to ignore
    minSecretLength    int                    // Minimum length to consider a secret
    maxSecretLength    int                    // Maximum length to consider a secret
    mu                 sync.RWMutex
}

// NewRegexManager creates a new regex manager
func NewRegexManager() *RegexManager {
    manager := &RegexManager{
        patterns:           make(map[string]*regexp.Regexp),
        exclusionPatterns:  make([]*regexp.Regexp, 0),
        excludedExtensions: []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"},
        minSecretLength:    5,   // Minimum of 5 characters to consider a secret
        maxSecretLength:    200, // Maximum of 200 characters to avoid entire code blocks
        mu:                 sync.RWMutex{},
    }
    
    // Register this manager globally so it can be reset if needed
    RegisterRegexManager(manager)
    
    return manager
}

// FindSecrets searches for secrets using the configured regex patterns
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
    rm.mu.RLock()
    patternCount := len(rm.patterns)
    rm.mu.RUnlock()
    
    if (patternCount == 0) {
        // Load predefined patterns once at the beginning
        rm.mu.Lock()
        err := rm.LoadPredefinedPatterns()
        patternCount = len(rm.patterns)
        rm.mu.Unlock()
        
        if err != nil {
            return nil, fmt.Errorf("failed to load predefined patterns: %w", err)
        }
        
        if patternCount == 0 {
            return nil, fmt.Errorf("no patterns loaded")
        }
    }
    
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    return rm.findSecretsWithFiltering(content, url, false)
}

// FindSecretsWithStrictFiltering is a version of FindSecrets that applies stricter filters for minified content
func (rm *RegexManager) FindSecretsWithStrictFiltering(content, url string) ([]Secret, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    return rm.findSecretsWithFiltering(content, url, true)
}

// findSecretsWithFiltering is the core implementation for searching secrets with optional filtering
func (rm *RegexManager) findSecretsWithFiltering(content, url string, strictMode bool) ([]Secret, error) {
    if len(rm.patterns) == 0 {
        return nil, fmt.Errorf("no regex patterns loaded")
    }

    // Check file extensions to ignore
    for _, ext := range rm.excludedExtensions {
        if strings.HasSuffix(strings.ToLower(url), ext) {
            return nil, nil
        }
    }

    var secrets []Secret
    
    // For each pattern, search in the content
    for patternName, pattern := range rm.patterns {
        // Try to find matches for this pattern
        matches := pattern.FindAllStringSubmatch(content, -1)
        
        for _, match := range matches {
            if len(match) > 0 {
                // Extract the actual secret value (first capture group or full match)
                value := match[0]
                if len(match) > 1 && match[1] != "" {
                    value = match[1]
                }
                
                // Skip empty values and extremely long values
                if len(value) < 4 || len(value) > 1000 {
                    continue
                }
                
                // Skip if the value looks like a test or example
                if strings.Contains(strings.ToLower(value), "example") || 
                   strings.Contains(strings.ToLower(value), "test") ||
                   strings.Contains(strings.ToLower(value), "sample") {
                    continue
                }
                
                // Create a secret with context
                context := rm.extractContext(content, value)
                secret := Secret{
                    Type:    patternName,
                    Value:   value,
                    Context: context,
                    URL:     url,
                }
                secrets = append(secrets, secret)
            }
        }
    }
    
    return secrets, nil
}

// extractContext extracts the context around the secret
func (rm *RegexManager) extractContext(content, value string) string {
    idx := strings.Index(content, value)
    if idx == -1 {
        return ""
    }
    
    // Extract 50 characters before and after the secret
    contextStart := idx - 50
    if contextStart < 0 {
        contextStart = 0
    }
    
    contextEnd := idx + len(value) + 50
    if contextEnd > len(content) {
        contextEnd = len(content)
    }
    
    return content[contextStart:contextEnd]
}

// isExcludedByContext checks if the context indicates that the match should be ignored
func (rm *RegexManager) isExcludedByContext(context string) bool {
    // Check global exclusion patterns
    for _, pattern := range rm.exclusionPatterns {
        if pattern.MatchString(context) {
            return true
        }
    }
    
    return false
}

// isValidSecret checks if the found value appears to be a valid secret
func (rm *RegexManager) isValidSecret(value string, patternType string) bool {
    // Check minimum and maximum length
    if len(value) < rm.minSecretLength || len(value) > rm.maxSecretLength {
        return false
    }
    
    // Specific checks based on pattern type
    switch {
    case strings.Contains(patternType, "twilio_account_sid"):
        // Check if it starts with AC and is not in a CSS or base64 context
        if !strings.HasPrefix(value, "AC") || 
            strings.Contains(value, "AAA") || 
            strings.Contains(value, "eJy") {
            return false
        }
        
        // Check if it is not in a likely CSS/style context
        styleKeywords := []string{"width", "height", "margin", "padding", "content"}
        for _, keyword := range styleKeywords {
            if strings.Contains(value, keyword) {
                return false
            }
        }
        
    case strings.Contains(patternType, "twilio_app_sid"):
        // Check if it starts with AP and is not in a CSS or base64 context
        if !strings.HasPrefix(value, "AP") || 
            strings.Contains(value, "AAA") || 
            strings.Contains(value, "eJy") {
            return false
        }
        
        // Check if it is not in a likely CSS/style context
        styleKeywords := []string{"width", "height", "margin", "padding", "content"}
        for _, keyword := range styleKeywords {
            if strings.Contains(value, keyword) {
                return false
            }
        }
        
    case strings.Contains(patternType, "Heroku API KEY") || 
        strings.Contains(patternType, "heroku"):
        // Check if it is in a UI configuration context
        uiContextKeywords := []string{"id:", "target", "element", "styleBlock", "applies"}
        for _, keyword := range uiContextKeywords {
            if strings.Contains(value, keyword) {
                return false
            }
        }
        
        // Check if it has a prefix or context indicating it is a Heroku key
        if !strings.Contains(strings.ToLower(value), "heroku") && 
            !strings.Contains(strings.ToLower(value), "api") && 
            !strings.Contains(strings.ToLower(value), "key") {
            // If there is no indication of being Heroku in the context, it is likely a common UUID
            return false
        }
        
    case strings.Contains(patternType, "aws_url") || strings.Contains(patternType, "s3"):
        // Avoid false positives for Amazon S3 URLs
        if strings.Contains(value, "TR/css3-selectors") {
            return false
        }
        if strings.Contains(value, "TR/2011/REC-css3-selectors") {
            return false
        }
        
    case strings.Contains(patternType, "base64") || strings.Contains(patternType, "token"):
        // For tokens, check if it looks like minified code
        codeKeywords := []string{"function", "return", "var ", "let ", "const ",
            "window.", "document.", "if(", "else{", "for(", "while(", "switch"}
        for _, keyword := range codeKeywords {
            if strings.Contains(value, keyword) {
                return false
            }
        }
    }

    // Additional validations for authorization patterns
    switch patternType {
    case "authorization_basic":
        // For Basic Auth, require Base64-like format 
        // Basic Auth typically follows the pattern: basic Base64(username:password)
        if !strings.HasPrefix(strings.ToLower(value), "basic ") {
            return false
        }
        
        // Extract the potential token part
        parts := strings.SplitN(value, " ", 2)
        if len(parts) < 2 || len(parts[1]) < 16 {
            return false
        }
        
        // Check if it looks like base64 encoding
        token := parts[1]
        if !utils.IsLikelyBase64(token) {
            return false
        }
        
        // Common words that shouldn't be treated as secrets
        commonWords := []string{"chart", "content", "information", "settings", "features"}
        for _, word := range commonWords {
            if strings.Contains(strings.ToLower(token), word) {
                return false
            }
        }
        
    case "authorization_api":
        // API keys usually don't have spaces and are fairly long
        if strings.Count(value, " ") > 1 || len(value) < 20 {
            return false
        }
        
        // Try to extract the actual key part
        parts := strings.FieldsFunc(value, func(r rune) bool {
            return r == ' ' || r == '=' || r == ':' || r == '"' || r == '\''
        })
        
        // Check if we have something that looks like a key
        hasValidKey := false
        for _, part := range parts {
            if len(part) >= 16 && !utils.IsCommonWord(part) {
                hasValidKey = true
                break
            }
        }
        
        if !hasValidKey {
            return false
        }
        
        // Check against common false positive patterns
        falsePatterns := []string{"api_language", "api_location", "api fails", "api error"}
        for _, pattern := range falsePatterns {
            if strings.Contains(strings.ToLower(value), pattern) {
                return false
            }
        }
    }
    
    return true
}

// LoadPatternsFromFile carrega padrões de um arquivo para o RegexManager
func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Parse patterns from file
	patterns, excludePatterns, specificExclusions, err := ParsePatternsFromFile(filePath)
	if (err != nil) {
		return err
	}

	// If no patterns were found, return error
	if (len(patterns) == 0) {
		return fmt.Errorf("no patterns found in file %s", filePath)
	}

	// Clear existing patterns
	rm.patterns = make(map[string]*regexp.Regexp)
	rm.exclusionPatterns = make([]*regexp.Regexp, 0)
	rm.patternExclusions = make(map[string][]*regexp.Regexp)

	// Compile and add each pattern
	for name, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if (err != nil) {
			return fmt.Errorf("failed to compile regex pattern '%s': %v", name, err)
		}
		rm.patterns[name] = re
	}

	// Compile and add exclude patterns
	
	// Add default exclude patterns first
	for _, pattern := range ExclusionPatterns {
		re, err := regexp.Compile(pattern)
		if (err != nil) {
			return fmt.Errorf("failed to compile exclude pattern '%s': %v", pattern, err)
		}
		rm.exclusionPatterns = append(rm.exclusionPatterns, re)
	}
	
	// Add custom exclude patterns
	for _, pattern := range excludePatterns {
		re, err := regexp.Compile(pattern)
		if (err != nil) {
			return fmt.Errorf("failed to compile exclude pattern '%s': %v", pattern, err)
		}
		rm.exclusionPatterns = append(rm.exclusionPatterns, re)
	}

	// Compile and add specific exclusions
	for patternName, exclusions := range specificExclusions {
		var compiledExclusions []*regexp.Regexp
		for _, exclusion := range exclusions {
			re, err := regexp.Compile(exclusion)
			if (err != nil) {
				return fmt.Errorf("failed to compile specific exclusion for '%s': %v", patternName, err)
			}
			compiledExclusions = append(compiledExclusions, re)
		}
		rm.patternExclusions[patternName] = compiledExclusions
	}

	return nil
}

// AddPattern adds a single regex pattern to the manager
func (rm *RegexManager) AddPattern(name, pattern string) error {
    re, err := regexp.Compile(pattern)
    if err != nil {
        return fmt.Errorf("failed to compile regex '%s': %v", name, err)
    }

    rm.mu.Lock()
    defer rm.mu.Unlock()

    rm.patterns[name] = re
    return nil
}

// RemovePattern removes a pattern from the manager
func (rm *RegexManager) RemovePattern(name string) {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    delete(rm.patterns, name)
}

// GetPatternNames returns the names of all patterns
func (rm *RegexManager) GetPatternNames() []string {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    names := make([]string, 0, len(rm.patterns))
    for name := range rm.patterns {
        names = append(names, name)
    }

    return names
}

// GetPatternCount returns the number of patterns
func (rm *RegexManager) GetPatternCount() int {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    return len(rm.patterns)
}

// ClearPatterns removes all patterns from the manager
func (rm *RegexManager) ClearPatterns() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    rm.patterns = make(map[string]*regexp.Regexp)
}

// HasPattern checks if a pattern exists
func (rm *RegexManager) HasPattern(name string) bool {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    _, exists := rm.patterns[name]
    return exists
}

// IsExcluded verifica se um match deve ser excluído
func (rm *RegexManager) IsExcluded(match string, patternName string) bool {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    // Verificar o comprimento do match
    if len(match) < rm.minSecretLength || len(match) > rm.maxSecretLength {
        return true
    }
    
    // Verificar nas exclusões específicas para este padrão primeiro
    if specificExclusions, exists := rm.patternExclusions[patternName]; exists {
        for _, re := range specificExclusions {
            if re.MatchString(match) {
                return true
            }
        }
    }
    
    // Verificar padrões de exclusão gerais
    for _, re := range rm.exclusionPatterns {
        if re.MatchString(match) {
            return true
        }
    }
    
    return false
}

// FindMatches finds all regex matches in content
func (rm *RegexManager) FindMatches(content, url string) map[string][]string {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    matches := make(map[string][]string)

    // Find matches for each pattern
    for name, re := range rm.patterns {
        found := re.FindAllString(content, -1)
        if len(found) > 0 {
            // Filter out duplicates
            unique := make(map[string]bool)
            for _, match := range found {
                // Skip excluded patterns
                if !rm.IsExcluded(match, name) {
                    unique[match] = true
                }
            }

            // Convert map keys to slice
            var uniqueMatches []string
            for match := range unique {
                uniqueMatches = append(uniqueMatches, match)
            }

            if len(uniqueMatches) > 0 {
                matches[name] = uniqueMatches
            }
        }
    }

    return matches
}

// Reset resets the RegexManager to its initial state
func (rm *RegexManager) Reset() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Only clear patterns if explicitly requested
    // This ensures we don't lose loaded patterns between runs
    if len(rm.patterns) == 0 {
        // We're already in a clean state
        return
    }
    
    // Don't fully reset - clear existing collections but don't destroy them
    for k := range rm.patterns {
        delete(rm.patterns, k)
    }
    
    rm.exclusionPatterns = make([]*regexp.Regexp, 0)
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    rm.excludedExtensions = []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"}
}

// CompleteReset performs a complete reset of the RegexManager to initial state
func (rm *RegexManager) CompleteReset() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Create fresh collections
    rm.patterns = make(map[string]*regexp.Regexp)
    rm.exclusionPatterns = make([]*regexp.Regexp, 0)
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    
    // Reset to default configuration
    rm.excludedExtensions = []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"}
    rm.minSecretLength = 5
    rm.maxSecretLength = 200
}