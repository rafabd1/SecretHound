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
                
                // Create a secret with context
                context := rm.extractContext(content, value)
                
                // Apply validation checks
                if rm.isExcludedByContext(context) {
                    continue
                }
                
                if !rm.isValidSecret(value, patternName) {
                    continue
                }
                
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

// FindMatches finds all regex matches in content and returns them directly
// This is especially useful for local file scanning
func (rm *RegexManager) FindMatches(content, url string) map[string][]string {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    matches := make(map[string][]string)

    // Check file extension to determine if any special handling is needed
    isLocalFile := strings.HasPrefix(url, "file://")
    needsStrictFiltering := false
    
    // Minified content needs more strict filtering
    if len(content) > 5000 && strings.Count(content, "\n") < 10 {
        needsStrictFiltering = true
    }

    // Find matches for each pattern
    for name, re := range rm.patterns {
        found := re.FindAllString(content, -1)
        if len(found) > 0 {
            // Filter out duplicates
            unique := make(map[string]bool)
            for _, match := range found {
                // Skip excluded patterns
                if !rm.IsExcluded(match, name) {
                    // Apply stricter validation for local files to reduce false positives
                    isValid := true
                    
                    if isLocalFile {
                        // Check if match is valid in local file context
                        isValid = rm.isLocalFileSecretValid(match, name, content)
                    } else if needsStrictFiltering {
                        // For minified content, apply stricter filtering
                        isValid = rm.isValidSecretStrict(match, name)
                    }
                    
                    if isValid {
                        unique[match] = true
                    }
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

// isLocalFileSecretValid performs additional validation for local file secrets
func (rm *RegexManager) isLocalFileSecretValid(match, patternName, content string) bool {
    // Always exclude very short or very long values
    if len(match) < rm.minSecretLength || len(match) > rm.maxSecretLength {
        return false
    }
    
    // Check for common code patterns that indicate false positives
    codePatterns := []string{
        "function", "return", "const ", "var ", "let ", 
        "import", "export", "require", "module", "class",
    }
    
    for _, pattern := range codePatterns {
        if strings.Contains(match, pattern) {
            return false
        }
    }
    
    // For strings like UUIDs, check if they're in a code context
    if strings.Contains(match, "-") && len(match) >= 32 && len(match) <= 40 {
        // Find where the match is in the content
        idx := strings.Index(content, match)
        if idx != -1 {
            // Look at surrounding context
            start := max(0, idx-20)
            end := min(len(content), idx+len(match)+20)
            context := content[start:end]
            
            // Check if this looks like a UUID assignment or declaration
            if strings.Contains(context, "uuid") || 
               strings.Contains(context, "UUID") ||
               strings.Contains(context, "id:") || 
               strings.Contains(context, "ID:") {
                return false
            }
        }
    }
    
    // Pattern-specific checks
    switch patternName {
    case "bearer_token":
        // Bearer tokens should not be UI elements
        if strings.Contains(match, "children") || 
           strings.Contains(match, "autoComplete") ||
           strings.Contains(match, "placeholder") {
            return false
        }
        
    case "high_entropy_string":
        // Skip anything that looks like a UUID
        if strings.Count(match, "-") == 4 && len(match) == 36 {
            return false
        }
        
        // Skip separator lines
        if strings.Contains(match, "----") {
            return false
        }
        
        // Skip React/Angular/Vue internals
        if strings.Contains(match, "UNSAFE_") || 
           strings.Contains(match, "INTERNAL") ||
           strings.Contains(match, "freshchat_") {
            return false
        }
        
        // Skip MIME types and content types
        if strings.Contains(match, "application/") ||
           strings.Contains(match, "text/") ||
           strings.Contains(match, "image/") ||
           strings.Contains(match, "charset=") {
            return false
        }
        
        // Skip file paths and module references
        if strings.Contains(match, "node_modules/") ||
           strings.Contains(match, "/modules/") ||
           strings.Contains(match, "/documentation") {
            return false
        }
        
        // Check surrounding context for indicators of non-secret content
        idx := strings.Index(content, match)
        if idx != -1 {
            // Get more context (60 chars before and after)
            start := max(0, idx-60)
            end := min(len(content), idx+len(match)+60)
            surroundContext := content[start:end]
            
            // Check for common patterns in surrounding context
            nonSecretContexts := []string{
                "contentType", "content-type", "application/",
                "node_modules", "documentation", "charset",
                "Content-Type", "import", "require", "export",
                "http://", "https://", ".html", ".js", ".css",
                ".min.", "webpack", "babel", "modules",
            }
            
            for _, ctx := range nonSecretContexts {
                if strings.Contains(surroundContext, ctx) {
                    return false
                }
            }
        }
        
    case "generic_password":
        // Verificar se está em arquivos de tradução ou internacionalização
        if strings.Contains(content, "i18n") || 
           strings.Contains(content, "localization") || 
           strings.Contains(content, "translation") {
            return false
        }
        
        // Verificar se é parte de uma mensagem de erro ou informação sobre senhas
        if strings.Contains(content, "password_") ||
           strings.Contains(content, "does_not_match") ||
           strings.Contains(content, "validation") {
            return false
        }
        
        // Verificar contexto próximo para determinar se é um valor real ou texto informativo
        idx := strings.Index(content, match)
        if idx != -1 {
            start := max(0, idx-50)
            end := min(len(content), idx+len(match)+50)
            surroundContext := content[start:end]
            
            // Verificar termos que indicam mensagens sobre senhas, não valores reais
            falsePositiveIndicators := []string{
                "match", "valid", "must", "should", "hint", "help", 
                "message", "error", "info", "confirm", "new", "old",
                "doesn't", "don't", "cannot", "requirements", "rules",
            }
            
            for _, indicator := range falsePositiveIndicators {
                if strings.Contains(strings.ToLower(surroundContext), indicator) {
                    return false
                }
            }
        }
        
    case "new_relic_license_key":
        // Verificar se é um padrão numérico repetitivo (como visto nos falsos positivos)
        if isRepetitiveDigitPattern(match) {
            return false
        }
        
        // Verificar se o conteúdo tem características de dados de timezone
        if strings.Contains(content, "GMT") || 
           strings.Contains(content, "UTC") || 
           strings.Contains(content, "/Accra") ||
           strings.Contains(content, "Africa/") ||
           strings.Contains(content, "America/") {
            return false
        }
        
        // Verificar se está em contexto de código minificado
        if !strings.Contains(content, "New Relic") && 
           !strings.Contains(content, "newrelic") && 
           !strings.Contains(content, "NREUM") {
            // Se não tem indício de ser um contexto New Relic, é provável que seja falso positivo
            return false
        }
        
    case "dropbox_long_token":
        // Verificar padrões repetitivos de números ou zeros e uns
        if isRepetitiveDigitPattern(match) || isRepetitiveBinaryPattern(match) {
            return false
        }
        
        // Verificar se está em contexto de timezone
        if strings.Contains(content, "GMT") || 
           strings.Contains(content, "UTC") || 
           strings.Contains(content, "Africa/") || 
           strings.Contains(content, "Europe/") {
            return false
        }
        
        // Verificar se está em contexto verdadeiro de Dropbox
        if !strings.Contains(content, "Dropbox") && 
           !strings.Contains(content, "dropbox") && 
           !strings.Contains(content, "DBX") {
            return false
        }
        
    case "coinbase_versioned_key":
        // Verificar se o padrão é de código minificado
        if hasMinifiedCodePattern(match) {
            return false
        }
        
        // Verificar se está em contexto verdadeiro de Coinbase
        if !strings.Contains(content, "Coinbase") && 
           !strings.Contains(content, "coinbase") {
            return false
        }
        
        // Verificar contexto próximo para determinar se é um valor real ou variável de código
        idx := strings.Index(content, match)
        if idx != -1 {
            start := max(0, idx-30)
            end := min(len(content), idx+len(match)+30)
            surroundContext := content[start:end]
            
            // Verificar se o contexto contém indícios de ser código
            codeIndicators := []string{
                "var ", "let ", "const ", "function", 
                "= [", "= {", "return", "this.", "new ",
            }
            
            for _, indicator := range codeIndicators {
                if strings.Contains(surroundContext, indicator) {
                    return false
                }
            }
        }
        
    case "twilio_account_sid":
        // Se não começa com AC, não é um Twilio Account SID
        if !strings.HasPrefix(match, "AC") {
            return false
        }
        
        // Verificar se o padrão é de código minificado
        if hasMinifiedCodePattern(match) {
            return false
        }
        
        // Verificar se está em contexto verdadeiro de Twilio
        if !strings.Contains(content, "Twilio") && 
           !strings.Contains(content, "twilio") {
            // Se não tem indício de ser um contexto Twilio, precisa ser ainda mais estrito
            if len(match) != 34 { // ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx tem 34 caracteres
                return false
            }
            
            // Verificar se parece um conjunto de variáveis minificadas
            variablePattern := regexp.MustCompile(`[A-Z]{1,2}[0-9]{1,2}[A-Z]{1,2}`)
            if variablePattern.MatchString(match[2:10]) {
                return false
            }
        }
    
    case "google_oauth_refresh":
        // Verificar se está em contexto de código minificado
        if strings.Contains(content, ".min.js") ||
           strings.Contains(content, "cdn.") ||
           strings.Contains(content, "app.js") {
            // Em arquivos minificados, precisamos de mais contexto para validar
            if !strings.Contains(content, "refresh_token") &&
               !strings.Contains(content, "oauth") {
                return false
            }
        }
        
        // Verificar por padrões de base64 aleatórios em JavaScript
        if hasRandomBase64Pattern(match) {
            return false
        }
        
        // Verificar se parece código minificado baseado no contexto
        surroundingContext := extractSurroundingContext(content, match, 50)
        if hasMinifiedPatternInContext(surroundingContext) {
            return false
        }
    
    case "oauth_token":
        // Verificar por caracteres inválidos para tokens OAuth verdadeiros
        if strings.ContainsAny(match, "':!#?") {
            return false
        }
        
        // Verificar por strings típicas de código minificado
        if strings.Contains(match, "QVO") ||
           strings.Contains(match, "QUO") ||
           strings.Contains(match, "YO") {
            return false
        }
        
        // Verificar se está em contexto de código minificado
        if strings.Contains(content, ".min.js") ||
           strings.Contains(content, "cdn.") ||
           strings.Contains(content, "app.js") {
            // Em arquivos minificados, precisamos de mais contexto para validar
            if !strings.Contains(content, "oauth_token") &&
               !strings.Contains(content, "access_token") {
                return false
            }
        }
        
        // Verificar o contexto ao redor para identificar código minificado
        surroundingContext := extractSurroundingContext(content, match, 40)
        if hasMinifiedPatternInContext(surroundingContext) {
            return false
        }
    
    case "google_measurement_id":
        // Verificar formato específico para IDs do Google Analytics
        if !regexp.MustCompile(`^G-[A-Z0-9]{10}$`).MatchString(match) {
            return false
        }
        
        // Verificar se está em contexto de código minificado
        if strings.Contains(content, ".min.js") ||
           strings.Contains(content, "cdn.") ||
           strings.Contains(content, "app.js") ||
           strings.Contains(content, "vendor.js") {
            
            // Em código minificado, verifique se o padrão parece uma variável
            if hasMinifiedCodePattern(match) {
                return false
            }
            
            // Verificar o contexto ao redor para identificar código minificado
            surroundingContext := extractSurroundingContext(content, match, 40)
            if hasMinifiedPatternInContext(surroundingContext) && 
               !strings.Contains(strings.ToLower(content), "google") &&
               !strings.Contains(strings.ToLower(content), "gtag") &&
               !strings.Contains(strings.ToLower(content), "analytics") {
                return false
            }
        }
    }
    
    return true
}

// isRepetitiveDigitPattern verifica se um valor é composto de dígitos repetitivos
func isRepetitiveDigitPattern(s string) bool {
    // Verificar se contém apenas dígitos
    if !regexp.MustCompile(`^[0-9]+$`).MatchString(s) {
        return false
    }
    
    // Verificar padrões repetitivos
    
    // Verificar se todos os dígitos são iguais
    firstDigit := s[0]
    sameDigitCount := 0
    for i := 0; i < len(s); i++ {
        if s[i] == firstDigit {
            sameDigitCount++
        }
    }
    
    // Se mais de 80% dos dígitos são iguais, é repetitivo
    if float64(sameDigitCount)/float64(len(s)) > 0.8 {
        return true
    }
    
    // Verificar repetição de padrões como "01", "12", etc.
    if len(s) >= 10 {
        // Verificar padrões de 1-3 dígitos
        for patternLength := 1; patternLength <= 3; patternLength++ {
            if len(s) < patternLength*3 {
                continue
            }
            
            pattern := s[0:patternLength]
            repetitionCount := 0
            
            for i := 0; i < len(s); i += patternLength {
                if i+patternLength <= len(s) {
                    if s[i:i+patternLength] == pattern {
                        repetitionCount++
                    }
                }
            }
            
            // Se o padrão se repete muitas vezes (cobre mais de 80% da string)
            if float64(repetitionCount*patternLength)/float64(len(s)) > 0.8 {
                return true
            }
        }
    }
    
    return false
}

// isRepetitiveBinaryPattern verifica se um valor é composto de padrões binários repetitivos (0s e 1s)
func isRepetitiveBinaryPattern(s string) bool {
    // Verificar se contém apenas 0s e 1s
    if !regexp.MustCompile(`^[01]+$`).MatchString(s) {
        return false
    }
    
    // Se a string for muito longa e composta apenas de 0s e 1s, é provável que seja um padrão binário
    if len(s) > 50 {
        return true
    }
    
    // Verificar repetição de padrões binários
    for patternLength := 1; patternLength <= 8; patternLength++ {
        if len(s) < patternLength*3 {
            continue
        }
        
        pattern := s[0:patternLength]
        repetitionCount := 0
        
        for i := 0; i < len(s); i += patternLength {
            if i+patternLength <= len(s) {
                if s[i:i+patternLength] == pattern {
                    repetitionCount++
                }
            }
        }
        
        // Se o padrão se repete muitas vezes (cobre mais de 70% da string)
        if float64(repetitionCount*patternLength)/float64(len(s)) > 0.7 {
            return true
        }
    }
    
    return false
}

// hasMinifiedCodePattern verifica se uma string tem características de código JavaScript minificado
func hasMinifiedCodePattern(s string) bool {
    // Padrões comuns em código minificado
    patterns := []struct {
        regex *regexp.Regexp
        threshold float64 // Percentual de ocorrências para considerar como código minificado
    }{
        {regexp.MustCompile(`[A-Z][0-9][A-Z]`), 0.3},           // Padrões como A1B, C2D, etc.
        {regexp.MustCompile(`[a-z][A-Z][0-9]`), 0.3},           // Padrões como aB1, cD2, etc.
        {regexp.MustCompile(`[0-9][A-Z][0-9]`), 0.3},           // Padrões como 1A2, 3B4, etc.
        {regexp.MustCompile(`[A-Z]{1,2}[0-9]{1,2}`), 0.4},      // Padrões como A1, BC23, etc.
    }
    
    for _, pattern := range patterns {
        matches := pattern.regex.FindAllString(s, -1)
        if len(matches) > 0 {
            // Calcular a porcentagem do texto que corresponde ao padrão
            matchedChars := 0
            for _, match := range matches {
                matchedChars += len(match)
            }
            
            matchPercentage := float64(matchedChars) / float64(len(s))
            if matchPercentage >= pattern.threshold {
                return true
            }
        }
    }
    
    return false
}

// hasRandomBase64Pattern verifica se uma string parece conter dados aleatórios de base64
func hasRandomBase64Pattern(s string) bool {
    // Remove o prefixo "1/" se existir
    if strings.HasPrefix(s, "1/") {
        s = s[2:]
    }
    
    // Verifica a entropia da string (presença de caracteres aleatórios)
    charFrequency := make(map[rune]int)
    for _, char := range s {
        charFrequency[char]++
    }
    
    // Uma distribuição equilibrada de caracteres indica aleatoriedade
    uniqueChars := len(charFrequency)
    
    // Para strings de tamanho razoável, se há muitos caracteres únicos e bem distribuídos,
    // provavelmente é uma string aleatória
    if len(s) > 20 && float64(uniqueChars)/float64(len(s)) > 0.5 {
        return true
    }
    
    return false
}

// extractSurroundingContext extrai o contexto próximo à string encontrada
func extractSurroundingContext(content, match string, size int) string {
    idx := strings.Index(content, match)
    if idx == -1 {
        return ""
    }
    
    start := max(0, idx-size)
    end := min(len(content), idx+len(match)+size)
    
    return content[start:end]
}

// hasMinifiedPatternInContext verifica se o contexto contém padrões típicos de código minificado
func hasMinifiedPatternInContext(context string) bool {
    // Padrões comuns em código JavaScript minificado
    minifiedPatterns := []string{
        // Sequências de variáveis curtas
        `[a-zA-Z][0-9][A-Z]`, 
        `[0-9][a-zA-Z][0-9]`,
        
        // Operadores sem espaços
        `\+\+`, `--`, `==`, `===`, `!=`, `!==`, `\?\?`, `\?\:`,
        
        // Sequências sem espaçamento adequado
        `\){`, `\){`, `\};`, `\}function`, `\}var`, `\}else`,
        
        // Funções minificadas
        `function\([a-z],`, `function\([a-z],[a-z]`,
        
        // Operações de atribuição sem espaços
        `=[a-z]\(`, `=[0-9]+`, `=\"`, `=\'`, `=\{`, `=\[`,
        
        // Pontuação densa típica de código minificado
        `\}\)\(`, `\)\}\(`, `\)\)\(`, `\}\}\(`,
    }
    
    for _, pattern := range minifiedPatterns {
        if regexp.MustCompile(pattern).MatchString(context) {
            return true
        }
    }
    
    // Verificar padrões específicos para strings órfãs e variáveis em código minificado
    codePatterns := []struct {
        regex string
        threshold int  // Número mínimo de ocorrências para considerar como código minificado
    }{
        {`[a-z][A-Z][0-9]`, 2},     // Padrões como aB1, cD2
        {`[A-Z][0-9][a-z]`, 2},     // Padrões como A1b, C2d
        {`\.[a-zA-Z]\(`, 2},        // Chamadas de método como .a(), .b()
        {`,[a-z],`, 2},             // Parâmetros curtos ,a,b,c,
        {`\d+[a-zA-Z]+\d+`, 2},     // Números misturados com letras 123abc456
    }
    
    for _, pattern := range codePatterns {
        matches := regexp.MustCompile(pattern.regex).FindAllString(context, -1)
        if len(matches) >= pattern.threshold {
            return true
        }
    }
    
    return false
}

// isValidSecretStrict applies stricter validation for secrets
func (rm *RegexManager) isValidSecretStrict(value string, patternType string) bool {
    if !rm.isValidSecret(value, patternType) {
        return false
    }

    // More strict length validation
    if len(value) < rm.minSecretLength*2 || len(value) > rm.maxSecretLength/2 {
        return false
    }

    // Verify if the value contains minified code patterns
    codeChars := []string{"{", "}", ";", "&&", "||", "==", "!=", "=>", "+=", "-="}
    for _, char := range codeChars {
        if strings.Contains(value, char) {
            return false
        }
    }
    
    // Check for repetitive patterns that indicate minified code
    if containsRepetitivePattern(value) {
        return false
    }

    return true
}

// containsRepetitivePattern checks for patterns indicating minified code
func containsRepetitivePattern(value string) bool {
    if len(value) < 20 {
        return false
    }
    
    // Check for sequences of repeating characters
    charCounts := make(map[rune]int)
    prevChar := ' '
    repeatCount := 1
    
    for _, char := range value {
        charCounts[char]++
        
        if char == prevChar {
            repeatCount++;
            if repeatCount > 5 {
                return true // More than 5 repeating chars
            }
        } else {
            repeatCount = 1
        }
        
        prevChar = char
    }
    
    // If one character represents more than 50% of the string and it's longer than 30 chars
    if len(value) > 30 {
        for _, count := range charCounts {
            if float64(count)/float64(len(value)) > 0.5 {
                return true
            }
        }
    }
    
    return false
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

