package utils

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// IsCommonWord checks if a string is a common word that shouldn't be treated as a secret
func IsCommonWord(s string) bool {
	commonWords := []string{
		"password", "username", "function", "return", "export", 
		"import", "require", "module", "class", "const", "default",
		"private", "protected", "public", "static", "application",
		"document", "window", "content", "charset", "modules",
	}
	
	s = strings.ToLower(s)
	for _, word := range commonWords {
		if s == word {
			return true
		}
	}
	
	return false
}

// IsLikelyBase64 checks if a string looks like it's base64 encoded
func IsLikelyBase64(s string) bool {
	if len(s) == 0 {
		return false
	}
	
	// Base64 strings are typically a multiple of 4 characters long
	// and end with 0-2 '=' characters for padding
	if len(s)%4 != 0 && !strings.HasSuffix(s, "=") && !strings.HasSuffix(s, "==") {
		return false
	}
	
	// Base64 strings only contain these characters
	base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Regex.MatchString(s)
}

// IsLikelyFilePath checks if a string appears to be a file path
func IsLikelyFilePath(s string) bool {
	// Check for path separators
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		// Look for file extensions or node_modules-like paths
		return strings.Contains(s, ".") || 
		       strings.Contains(s, "node_modules") ||
		       strings.Contains(s, "dist") ||
		       strings.Contains(s, "src") ||
		       strings.Contains(s, "modules")
	}
	return false
}

// IsLikelyContentType checks if a string appears to be a content type
func IsLikelyContentType(s string) bool {
	contentTypePatterns := []string{
		"application/", "text/", "image/", "audio/", "video/",
		"multipart/", "charset=", "content-type", "contentType",
	}
	
	for _, pattern := range contentTypePatterns {
		if strings.Contains(strings.ToLower(s), pattern) {
			return true
		}
	}
	
	return false
}

// HasCommonCodePattern checks if a string contains common code patterns
func HasCommonCodePattern(s string) bool {
	patterns := []string{
		"function", "return", "const ", "var ", "let ", 
		"import ", "export ", "require(", "module.", "class ",
		"interface ", "typeof ", "console.", "window.", "document.",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	
	return false
}

// IsLikelyTranslationKey verifica se uma string parece ser uma chave de tradução/internacionalização
func IsLikelyTranslationKey(s string) bool {
    // Chaves de tradução geralmente são snake_case ou camelCase e têm palavras como
    // "text", "message", "label", "title", "description", "error", etc.
    translationIndicators := []string{
        "_text", "_msg", "_message", "_label", "_title", "_description", 
        "_error", "_info", "_hint", "_help", "_tooltip", "_placeholder",
        "_button", "_link", "_heading", "_flash", "_notification", 
        "_trend", "_chart", "_enabled", "_disabled", "_by_", "_and_",
    }
    
    for _, indicator := range translationIndicators {
        if strings.Contains(strings.ToLower(s), indicator) {
            return true
        }
    }
    
    // Se tiver muitos underscores/separadores, provavelmente é uma chave de tradução
    if strings.Count(s, "_") >= 3 || strings.Count(s, ".") >= 2 {
        return true
    }
    
    return false
}

// IsValidSecretCandidate faz uma verificação abrangente se um valor parece um segredo válido
func IsValidSecretCandidate(secretType, value, context string) bool {
    // Verificar comprimento mínimo baseado no tipo
    minLength := 8 // Padrão
    switch secretType {
    case "aws_key", "stripe_api_key", "google_api":
        minLength = 16
    case "jwt_token", "bearer_token":
        minLength = 20
    }
    
    if len(value) < minLength {
        return false
    }
    
    // Verificar se parece chave de tradução/internacionalização
    if IsLikelyTranslationKey(value) {
        return false
    }
    
    // Verificar se contém palavras comuns de código
    if HasCommonCodePattern(value) {
        return false
    }
    
    // Verificar se é um caminho ou tipo de conteúdo
    if IsLikelyFilePath(value) || IsLikelyContentType(value) {
        return false
    }
    
    // Verificar pela presença de separadores em quantidades que indicam configuração ou ID
    // UUIDs e outros IDs frequentemente têm separadores
    if strings.Count(value, "-") >= 4 || strings.Count(value, ".") >= 5 {
        // Verificar se parece um UUID
        if strings.Count(value, "-") == 4 && len(value) >= 32 && len(value) <= 36 {
            dashPositions := []int{8, 13, 18, 23}
            isUUID := true
            
            for _, pos := range dashPositions {
                if pos >= len(value) || value[pos] != '-' {
                    isUUID = false
                    break
                }
            }
            
            if isUUID {
                return false
            }
        }
    }
    
    return true
}

// IsTimeZoneData checks if a string appears to contain timezone/geographic data
func IsTimeZoneData(s string) bool {
    // Check for common timezone markers
    timeZoneIndicators := []string{
        "GMT", "UTC", "EST", "CST", "MST", "PST", "CET", "MSD",
        "Africa/", "America/", "Asia/", "Europe/", "Pacific/",
        "|LMT|", "|GMT|", "|BST|", "|CET|", "|CEST|",
    }
    
    lowerS := strings.ToLower(s)
    for _, indicator := range timeZoneIndicators {
        if strings.Contains(lowerS, strings.ToLower(indicator)) {
            return true
        }
    }
    
    // Check for repeated digit patterns commonly found in timezone data
    digitPatterns := []string{
        "01212", "12121", "01010", "10101", "76767", "67676",
    }
    
    for _, pattern := range digitPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

// IsMinifiedVariableSequence checks if a string looks like minified code variable sequence
func IsMinifiedVariableSequence(s string) bool {
    // Check for characteristic minified JS variable patterns
    patterns := []*regexp.Regexp{
        regexp.MustCompile(`[A-Z][0-9][A-Z][0-9]`),              // A1B2
        regexp.MustCompile(`[a-z][A-Z][0-9][a-z][A-Z]`),         // aB1cD
        regexp.MustCompile(`[A-Z]{1,2}[0-9]{1,2}[A-Z]{1,2}`),    // AB12CD
    }
    
    matchCount := 0
    for _, pattern := range patterns {
        matches := pattern.FindAllString(s, -1)
        matchCount += len(matches)
        
        // If we find multiple matches of these patterns, it's likely minified code
        if matchCount >= 3 {
            return true
        }
    }
    
    // Check for sequences of short variable-like segments
    segments := splitCamelOrNumberCase(s)
    if len(segments) >= 5 {
        shortSegmentCount := 0
        for _, segment := range segments {
            if len(segment) <= 3 {
                shortSegmentCount++
            }
        }
        
        // If more than 70% of segments are short (1-3 chars), likely minified
        if float64(shortSegmentCount)/float64(len(segments)) > 0.7 {
            return true
        }
    }
    
    return false
}

// splitCamelOrNumberCase splits a string at camel case boundaries or number sequences
func splitCamelOrNumberCase(s string) []string {
    if s == "" {
        return []string{}
    }
    
    var result []string
    var current strings.Builder
    
    // Helper to add current segment if not empty
    addCurrent := func() {
        if current.Len() > 0 {
            result = append(result, current.String())
            current.Reset()
        }
    }
    
    prevIsUpper := false
    prevIsLower := false
    prevIsDigit := false
    
    for i, r := range s {
        isUpper := unicode.IsUpper(r)
        isLower := unicode.IsLower(r)
        isDigit := unicode.IsDigit(r)
        
        // Always add the first character
        if i == 0 {
            current.WriteRune(r)
            prevIsUpper = isUpper
            prevIsLower = isLower
            prevIsDigit = isDigit
            continue
        }
        
        // Split at boundaries like:
        // - lowercase to uppercase (aB)
        // - uppercase to lowercase, but only after multiple uppercase (ABc)
        // - letter to digit or digit to letter (a1 or 1a)
        if (prevIsLower && isUpper) || 
           (prevIsUpper && isLower && i >= 2 && unicode.IsUpper(rune(s[i-2]))) ||
           (prevIsDigit && !isDigit) || 
           (!prevIsDigit && isDigit) {
            addCurrent()
        }
        
        current.WriteRune(r)
        prevIsUpper = isUpper
        prevIsLower = isLower
        prevIsDigit = isDigit
    }
    
    // Add the last segment
    addCurrent()
    
    return result
}

// IsLikelyUnicodePlaneReference checks if the content likely refers to Unicode planes like BMP
func IsLikelyUnicodePlaneReference(content string) bool {
    unicodeTerms := []string{
        "Basic Multilingual Plane", "BMP", "surrogate pair",
        "code point", "Unicode", "UTF-16", "UTF-8", "character encoding",
    }
    
    lowerContent := strings.ToLower(content)
    for _, term := range unicodeTerms {
        if strings.Contains(lowerContent, strings.ToLower(term)) {
            return true
        }
    }
    
    return false
}

// IsPatternInMinifiedCode verifica se um padrão aparece em contexto de código minificado
func IsPatternInMinifiedCode(value, context string) bool {
    // Verificar se o contexto contém características de código minificado
    minifiedIndicators := []string{
        // Operadores sem espaços
        "++", "--", "==", "===", "!=", "!==", "+=", "-=", "*=", "/=",
        
        // Encadeamento de funções e operações
        ".push(", ".pop(", ".shift(", ".map(", ".filter(", ".forEach(",
        
        // Outros indicadores de código minificado
        "function(", "return ", ";var ", ";let ", ";const ", "&&", "||",
    }
    
    // Se pelo menos 3 indicadores estiverem presentes, provavelmente é código minificado
    indicatorCount := 0
    for _, indicator := range minifiedIndicators {
        if strings.Contains(context, indicator) {
            indicatorCount++
            if indicatorCount >= 3 {
                return true
            }
        }
    }
    
    // Verificar padrões de variáveis minificadas
    minifiedVarPatterns := []string{
        `[a-z]\.[a-z]\.[a-z]`, // Padrões como a.b.c
        `[a-z]\([a-z],[a-z]\)`, // Funções como a(b,c)
        `var [a-z]=[^;]+,[a-z]=`, // Múltiplas atribuições var a=1,b=2
    }
    
    for _, pattern := range minifiedVarPatterns {
        if regexp.MustCompile(pattern).MatchString(context) {
            return true
        }
    }
    
    // Verificar se o valor em si parece uma variável de código minificado
    if regexp.MustCompile(`^[A-Za-z][0-9][A-Za-z][0-9]`).MatchString(value) ||
       regexp.MustCompile(`[a-z][A-Z][0-9][a-z][A-Z]`).MatchString(value) {
        return true
    }
    
    return false
}

// IsGoogleAnalyticsID verifica se um valor parece um ID legítimo do Google Analytics
func IsGoogleAnalyticsID(value string) bool {
    // Padrão específico para IDs do Google Analytics: G- seguido de exatamente 10 caracteres alfanuméricos
    if !regexp.MustCompile(`^G-[A-Z0-9]{10}$`).MatchString(value) {
        return false
    }
    
    // Verificar se não parece um padrão de variável minificada (como G-12AB34CD5)
    if regexp.MustCompile(`G-\d{1,2}[A-Z]{1,2}\d{1,2}[A-Z]{1,2}\d{1,2}`).MatchString(value) {
        return false
    }
    
    return true
}

// IsOAuthTokenInValidContext verifica se um token OAuth aparece em um contexto válido
func IsOAuthTokenInValidContext(value, context string) bool {
    // Verificar por termos que indicam contexto de autenticação
    authIndicators := []string{
        "oauth", "token", "access_token", "refresh_token", "bearer", 
        "authentication", "authorization", "credentials",
    }
    
    // Contar quantos indicadores estão presentes no contexto
    indicatorCount := 0
    for _, indicator := range authIndicators {
        if strings.Contains(strings.ToLower(context), indicator) {
            indicatorCount++
        }
    }
    
    // Se pelo menos 2 indicadores estão presentes, provavelmente é um contexto válido
    return indicatorCount >= 2
}

// IsLikelyCSS checks if a string appears to be a CSS variable or class
func IsLikelyCSS(s string) bool {
    // Check for CSS variables that start with --
    if strings.HasPrefix(s, "--") {
        return true
    }
    
    // Check for CSS class patterns with hyphens
    cssPatterns := []string{
        "-background-", "-color", "-radius", "-distance", "-shadow",
        "-border-", "-margin-", "-padding-", "-font-", "-size-",
        "-hover", "-active", "-focus", "-selected", "-disabled",
    }
    
    for _, pattern := range cssPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

// IsLikelyBase64Data checks if string looks like a valid base64 data or token
func IsLikelyBase64Data(s string) bool {
    // Already have IsLikelyBase64 function, but enhance for specific cases
    
    // Check for base64 image data
    if strings.Contains(s, "data:image") || 
       strings.Contains(s, "base64") {
        return true
    }
    
    // Check for JWT or origin-trial tokens which are base64 encoded
    if len(s) > 40 && IsLikelyBase64(s) {
        return true
    }
    
    return false
}

// IsUUID checks if a string is a valid UUID
func IsUUID(s string) bool {
    uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
    return uuidRegex.MatchString(s)
}

// HasRepeatedCharacterPattern checks if a string contains a suspiciously high number of repeated characters
func HasRepeatedCharacterPattern(s string) bool {
    if len(s) < 20 {
        return false
    }
    
    // Check for runs of the same character
    var prevChar rune
    runLength := 1
    maxRunLength := 0
    
    for i, char := range s {
        if i > 0 {
            if char == prevChar {
                runLength++
            } else {
                runLength = 1
            }
        }
        
        if runLength > maxRunLength {
            maxRunLength = runLength
        }
        
        prevChar = char
    }
    
    // If there are very long runs of the same character, likely not a secret
    if maxRunLength >= 6 {
        return true
    }
    
    // Check for repeating patterns like 'NNNLLLNNNLLL'
    charCounts := make(map[rune]int)
    for _, char := range s {
        charCounts[char]++
    }
    
    // If we have just a few character types repeated many times
    if len(charCounts) <= 5 && len(s) >= 30 {
        for _, count := range charCounts {
            // If any character appears more than 30% of the time
            if float64(count)/float64(len(s)) > 0.3 {
                return true
            }
        }
    }
    
    return false
}

// IsLikelyDocumentation checks if a string appears to be part of documentation
func IsLikelyDocumentation(s, context string) bool {
    // Documentation keywords
    docKeywords := []string{
        "example", "usage", "documentation", "wiki", "github.com", 
        "http://", "https://", "/docs/", "/documentation/", 
        "@example", "@caption", "@see", "@link", "sample", "tutorial",
    }
    
    for _, keyword := range docKeywords {
        if strings.Contains(strings.ToLower(s), keyword) || 
           strings.Contains(strings.ToLower(context), keyword) {
            return true
        }
    }
    
    return false
}

// IsLikelyI18nKey checks if a string appears to be an internationalization key
func IsLikelyI18nKey(s string) bool {
    // I18n keys often follow patterns like module_section_key
    if strings.Count(s, "_") >= 2 && len(s) > 20 {
        // Many words separated by underscores
        return true
    }
    
    // Common i18n key prefixes
    i18nPrefixes := []string{
        "message_", "label_", "error_", "success_", "button_",
        "placeholder_", "tooltip_", "hint_", "alert_", "text_",
        "title_", "description_", "header_", "footer_", "nav_",
        "min_", "max_", "app_", "page_", "dialog_", "LOGIN.",
        "freshchat_", "ui_", "validation_",
    }
    
    for _, prefix := range i18nPrefixes {
        if strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
            return true
        }
    }
    
    return false
}

// IsLikelyFunctionName checks if a string appears to be a camelCase function name
func IsLikelyFunctionName(s string) bool {
    // Check for typical function name pattern (camelCase starting with lowercase)
    functionRegex := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+$`)
    if functionRegex.MatchString(s) {
        return true
    }
    
    // Function names often contain action verbs
    actionVerbs := []string{
        "get", "set", "update", "delete", "create", "find", "fetch",
        "compute", "calculate", "validate", "parse", "format", "convert",
        "transform", "handle", "process", "initialize", "start", "stop",
        "transition", "register", "unregister", "subscribe", "unsubscribe",
    }
    
    for _, verb := range actionVerbs {
        if strings.HasPrefix(strings.ToLower(s), verb) {
            return true
        }
    }
    
    return false
}

// IsLikelyBasicAuthSyntax checks if a string contains "Basic" as part of authentication syntax or documentation
func IsLikelyBasicAuthSyntax(value, context string) bool {
    // If it's just the word "Basic" or "Basic " or "Basic usage" without credentials, it's likely a false positive
    if value == "Basic" || value == "Basic " || strings.HasPrefix(value, "Basic usage") {
        return true
    }
    
    // Check if it's within documentation
    docPatterns := []string{
        "@example", "example", "caption", "sample", "usage",
        "<caption>", "documentation",
    }
    
    for _, pattern := range docPatterns {
        if strings.Contains(strings.ToLower(context), pattern) {
            return true
        }
    }
    
    // If Basic is followed by a proper base64 string, it might be real
    if strings.HasPrefix(value, "Basic ") {
        credentials := strings.TrimPrefix(value, "Basic ")
        if IsLikelyBase64(credentials) && len(credentials) > 10 {
            // This looks like real Basic Auth
            return false
        }
    }
    
    return true
}

// IsLikelyUrl checks if a string looks like a URL path or fragment
func IsLikelyUrl(s string) bool {
    // Check for URL patterns
    urlPatterns := []string{
        ".com/", ".io/", ".net/", ".org/", ".edu/", ".gov/",
        "/api/", "/docs/", "/sdk/", "/plugins/", "/wiki/",
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    }
    
    for _, pattern := range urlPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

// IsJavaScriptFunction verifica se uma string é um nome de função JavaScript
func IsJavaScriptFunction(s string) bool {
	// JavaScript functions are typically camelCase and often contain verb prefixes
	verbPrefixes := []string{
		"get", "set", "update", "create", "delete", "remove", "handle", "process",
		"parse", "format", "convert", "validate", "verify", "check", "is", "has",
		"can", "should", "will", "did", "fetch", "load", "save", "store", "cache",
		"transition", "transform", "enable", "disable", "toggle", "show", "hide",
		"open", "close", "start", "stop", "begin", "end", "init", "setup", "enroll",
		"authenticate", "authorize", "login", "logout", "register", "subscribe",
		"unsubscribe", "connect", "disconnect", "mount", "unmount", "render", "display",
	}
	
	// Check for camelCase pattern
	if regexp.MustCompile(`^[a-z][a-zA-Z0-9]*([A-Z][a-zA-Z0-9]*)+$`).MatchString(s) {
		// Check if starts with common verb prefixes
		for _, prefix := range verbPrefixes {
			if strings.HasPrefix(strings.ToLower(s), prefix) {
				return true
			}
		}
		
		// Additional check for method-style names like "componentDidMount"
		components := []string{
			"component", "element", "handler", "listener", "callback", 
			"effect", "reducer", "action", "selector", "container",
			"provider", "consumer", "context", "fragment", "memo", "ref",
		}
		
		events := []string{
			"Mount", "Unmount", "Update", "Change", "Click", "Submit", 
			"Focus", "Blur", "KeyDown", "KeyUp", "MouseOver", "MouseOut",
			"TouchStart", "TouchEnd", "Drag", "Drop", "Resize", "Scroll",
		}
		
		for _, comp := range components {
			for _, event := range events {
				pattern := comp + event
				if strings.Contains(s, pattern) {
					return true
				}
				
				// Check for "did", "will", "on", "after", "before" patterns
				eventPatterns := []string{"Did" + event, "Will" + event, "On" + event, "After" + event, "Before" + event}
				for _, ep := range eventPatterns {
					if strings.Contains(s, ep) {
						return true
					}
				}
			}
		}
	}
	
	// Check for common MFA/authentication related function patterns
	authPatterns := []string{
		"MFA", "2FA", "TwoFactor", "MultiFactorAuth", "AuthFactor",
		"Verify", "Validate", "Authenticate", "Authorize", "Token",
		"Credential", "Password", "Login", "Logout", "Session",
		"Remember", "Forgot", "Reset", "Change", "Update", "Check",
	}
	
	for _, pattern := range authPatterns {
		// Look for camelCase combinations with auth patterns
		if regexp.MustCompile(fmt.Sprintf(`(?i)(transition|verify|enable|display|is|has|can)[A-Z][a-zA-Z]*%s`, pattern)).MatchString(s) {
			return true
		}
		
		// Also check for patterns like "isMFAEnabled", "hasTwoFactor", etc.
		if regexp.MustCompile(fmt.Sprintf(`(?i)(is|has|can|should|will|did)%s[A-Z][a-zA-Z]*`, pattern)).MatchString(s) {
			return true
		}
	}
	
	return false
}

// IsJavaScriptConstant verifica se uma string parece ser uma constante JavaScript
func IsJavaScriptConstant(s string) bool {
	// JavaScript constants are typically UPPER_CASE or PascalCase for enum-like values
	
	// Check for UPPER_CASE with underscores
	if regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(s) {
		return true
	}
	
	// Check for enumeration-like constants with underscores
	if regexp.MustCompile(`^[A-Z][A-Z0-9_]*_[A-Z][A-Z0-9_]*$`).MatchString(s) {
		return true
	}
	
	// Check for common const naming patterns in JavaScript
	constPrefixes := []string{
		"DEFAULT_", "MAX_", "MIN_", "REQUIRED_", "OPTIONAL_", "CONFIG_",
		"TYPE_", "MODE_", "STATE_", "STATUS_", "EVENT_", "ACTION_",
		"ERROR_", "SUCCESS_", "WARNING_", "INFO_", "DEBUG_", "LOG_",
		"AUTH_", "USER_", "ADMIN_", "CLIENT_", "SERVER_", "APP_",
		"PERMISSION_", "ROLE_", "FEATURE_", "FLAG_", "TOGGLE_",
	}
	
	for _, prefix := range constPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	
	return false
}

// IsLikelyMinifiedCode checks if content appears to be minified JavaScript
func IsLikelyMinifiedCode(content string) bool {
	// Minified JavaScript typically has few newlines and many semicolons 
	// or has very long lines
	
	// Few newlines relative to length
	newlineCount := strings.Count(content, "\n")
	if len(content) > 200 && newlineCount < len(content)/200 {
		return true
	}
	
	// Many semicolons relative to newlines
	semicolonCount := strings.Count(content, ";")
	if newlineCount > 0 && semicolonCount > newlineCount*3 {
		return true
	}
	
	// Compressed variable names (single letters followed by operators)
	compressedVarPattern := regexp.MustCompile(`[a-z]\.[a-z]\.|[a-z]\([a-z],[a-z]\)|var [a-z]=[^;]+,[a-z]=|[a-z]\+\+|[a-z]--`)
	if compressedVarPattern.FindString(content) != "" {
		return true
	}
	
	// Look for minification artifacts
	minificationPatterns := []string{
		"}function", "};function", ";var ", ";let ", ";const ",
		"return ", ".push(", ".pop(", ".shift(", ".map(", ".filter(",
		"function(", "=>", "&&", "||",
	}
	
	matchCount := 0
	for _, pattern := range minificationPatterns {
		if strings.Contains(content, pattern) {
			matchCount++
		}
		
		if matchCount >= 3 {
			return true
		}
	}
	
	return false
}

// HasJavaScriptCamelCasePattern verifica se a string segue padrões de camelCase do JavaScript
func HasJavaScriptCamelCasePattern(s string) bool {
	// Verifica o padrão básico de camelCase
	if !regexp.MustCompile(`^[a-z][a-zA-Z0-9]*([A-Z][a-zA-Z0-9]*)+$`).MatchString(s) {
		return false
	}
	
	// Palavras comuns em nomes camelCase em JavaScript
	commonWords := []string{
		"transition", "verify", "enable", "disable", "display", "update", "create",
		"delete", "remove", "get", "set", "handle", "process", "parse", "format",
		"convert", "validate", "check", "is", "has", "can", "should", "will", "did",
		"fetch", "load", "save", "store", "cache", "transform", "toggle", "show",
		"hide", "open", "close", "start", "stop", "begin", "end", "init", "setup",
		"register", "subscribe", "unsubscribe", "connect", "disconnect", "mount",
		"unmount", "render", "component", "element", "handler", "listener", "callback",
		"effect", "reducer", "action", "selector", "container", "provider", "consumer",
		"context", "fragment", "memo", "ref", "state", "props", "hook", "custom",
		"use", "bind", "apply", "call", "memoize", "debounce", "throttle",
		"MFA", "2FA", "TwoFactor", "Auth", "Factor", "Token", "Credential", "Password",
		"Login", "Logout", "Session", "Remember", "Forgot", "Reset", "Change", "Update",
	}
	
	// Transforma camelCase em palavras separadas
	words := splitCamelCase(s)
	
	// Se alguma das palavras comuns estiver presente
	for _, word := range words {
		for _, common := range commonWords {
			if strings.EqualFold(word, common) {
				return true
			}
		}
	}
	
	return false
}

// Função auxiliar para dividir uma string camelCase em palavras separadas
func splitCamelCase(s string) []string {
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

// IsLikelyOriginTrialToken verifica se um token JWT parece ser um token de Origin Trial
func IsLikelyOriginTrialToken(value, context string) bool {
    // Origin Trial tokens aparecem frequentemente em contextos específicos
    originTrialIndicators := []string{
        "origin-trial", "originTrial", 
        "content=", "meta http-equiv", 
        "feature", "expiry", "isThirdParty", 
        "recaptcha", "gstatic", "google",
    }
    
    contextLower := strings.ToLower(context)
    indicatorCount := 0
    
    for _, indicator := range originTrialIndicators {
        if strings.Contains(contextLower, indicator) {
            indicatorCount++
        }
    }
    
    // Se tiver pelo menos 2 indicadores, provavelmente é um token de Origin Trial
    return indicatorCount >= 2
}

// IsVariableReference verifica se o valor é uma referência de variável/atribuição em código
func IsVariableReference(value, context string) bool {
    variablePatterns := []string{
        // Referências de variável
        ".accessToken", 
        "=access_token", 
        ":access_token",
        "oauth_token=",
        
        // Identificadores em atribuições
        "accessToken:",
        "token:",
        "credential:",
        
        // Nomes de propriedades em objetos
        "\"accessToken\"",
        "'accessToken'",
    }
    
    for _, pattern := range variablePatterns {
        if strings.Contains(value, pattern) {
            return true
        }
    }
    
    // Verificar se parece uma atribuição de variável
    assignmentPattern := regexp.MustCompile(`^\s*[a-zA-Z0-9_]+\s*[.:=]\s*[a-zA-Z0-9_\.]+\s*$`)
    return assignmentPattern.MatchString(value)
}

// IsUITextOrLabel verifica se o valor parece texto de UI ou label
func IsUITextOrLabel(value, context string) bool {
    // Textos comuns de UI relacionados a senhas
    uiLabels := []string{
        "Change password", "Reset password", "Forgot password",
        "Change Password", "Reset Password", "Forgot Password",
        "changingPassword", "resetPassword", "forgotPassword",
        "Password:", "Username:", "Email:", 
        "password", "PASSWORD", "Password",
    }
    
    for _, label := range uiLabels {
        if value == label {
            return true
        }
    }
    
    // Verificar se o contexto sugere um texto de UI (componentes React, Angular, etc)
    uiContexts := []string{
        "createElement", "component", "render", "label", 
        "button", "form", "input", "<label", "<input", 
        "type=\"password\"", "type=\"text\"", "placeholder",
    }
    
    contextLower := strings.ToLower(context)
    for _, uiContext := range uiContexts {
        if strings.Contains(contextLower, strings.ToLower(uiContext)) {
            return true
        }
    }
    
    return false
}

// IsUnicodeReference verifica se a string está em um contexto de referência Unicode
func IsUnicodeReference(value, context string) bool {
    // Termos relacionados a Unicode
    unicodeTerms := []string{
        "Unicode", "UTF", "UTF-8", "UTF-16", "BMP", "Basic Multilingual",
        "Surrogate", "Code Point", "Encoding", "Character Set", "Charset",
        "fromCharCode", "charCodeAt",
    }
    
    for _, term := range unicodeTerms {
        if strings.Contains(value, term) {
            return true
        }
        
        if strings.Contains(context, term) {
            return true
        }
    }
    
    return false
}

// IsGoogleFontApiKey verifica se a API key é do Google Fonts (menos sensível)
func IsGoogleFontApiKey(value, context string) bool {
    // Verificar se é uma API key do Google/Firebase (formato AIza...)
    if !strings.HasPrefix(value, "AIza") {
        return false
    }
    
    // Verificar se o contexto sugere Google Fonts
    googleFontsIndicators := []string{
        "googleapis.com/webfonts", 
        "fonts.googleapis.com",
        "google.fonts",
        "webfonts",
        "fonts?key=",
    }
    
    for _, indicator := range googleFontsIndicators {
        if strings.Contains(context, indicator) {
            return true
        }
    }
    
    return false
}

// IsDOMSelectorOrPseudo verifica se é um seletor DOM ou pseudoclasse em jQuery/CSS
func IsDOMSelectorOrPseudo(value, context string) bool {
    // Pseudoclasses CSS comuns
    pseudoClasses := []string{
        ":hover", ":active", ":focus", ":checked", ":disabled", 
        ":enabled", ":first-child", ":last-child", ":nth-child",
        ":radio", ":checkbox", ":file", ":password", ":image",
    }
    
    for _, pseudo := range pseudoClasses {
        if strings.Contains(value, pseudo) || value == strings.TrimPrefix(pseudo, ":") {
            return true
        }
    }
    
    // Verificar contexto de seletores jQuery ou similares
    selectorContexts := []string{
        "querySelector", "querySelectorAll", "getElementById", 
        "getElementsBy", "$('", "$(\"", "jQuery", "selector",
        "pseudos", "Expr.pseudos", "input[type=",
    }
    
    for _, selectorContext := range selectorContexts {
        if strings.Contains(context, selectorContext) {
            return true
        }
    }
    
    return false
}

// IsUIHeaderOrTitle verifica se o valor parece ser um cabeçalho de UI ou título
func IsUIHeaderOrTitle(value, context string) bool {
    // Lista de palavras comuns em cabeçalhos de UI
    uiHeaderTerms := []string{
        "authorization", "authentication", "configuration", "settings",
        "credentials", "login", "register", "profile", "account",
        "security", "management", "overview", "details", "information",
    }
    
    // Verifica componentes de UI comuns que indicam cabeçalhos
    uiHeaderComponents := []string{
        "<h1", "<h2", "<h3", "<h4", "<h5", "<h6",
        "createElement(\"h", "createElement('h", ".createElement(h",
        "title>", "<title", "header>", "<header",
    }
    
    // Verifica se o contexto contém componentes de cabeçalho
    for _, component := range uiHeaderComponents {
        if strings.Contains(context, component) {
            // Verifica se o valor começa com "Basic" e é seguido por uma palavra de cabeçalho
            if strings.HasPrefix(value, "Basic ") {
                suffix := strings.TrimPrefix(value, "Basic ")
                
                for _, term := range uiHeaderTerms {
                    if strings.EqualFold(suffix, term) {
                        return true
                    }
                }
            }
            
            // Também verifica por termos completos como "Basic authorization"
            for _, term := range uiHeaderTerms {
                if strings.HasPrefix(strings.ToLower(value), "basic "+term) {
                    return true
                }
            }
        }
    }
    
    return false
}

// IsValidJWTToken verifica se uma string com prefixo "eyJ" é um token JWT válido
func IsValidJWTToken(value string) bool {
    // JWT tokens reais geralmente têm 3 partes separadas por "."
    parts := strings.Split(value, ".")
    
    // Um token JWT válido deve ter exatamente 3 partes
    if len(parts) != 3 {
        return false
    }
    
    // Todas as partes devem ser strings base64 válidas
    for _, part := range parts {
        if !IsLikelyBase64(part) {
            return false
        }
    }
    
    // O header (primeira parte) geralmente é curto, e o payload (segunda parte) 
    // geralmente é mais longo que o header
    if len(parts[0]) < 10 || len(parts[1]) < len(parts[0]) {
        return false
    }
    
    // A terceira parte (assinatura) geralmente também tem um tamanho mínimo
    if len(parts[2]) < 16 {
        return false
    }
    
    // Verificação adicional - JWT reais geralmente têm estrutura de payload JSON específica
    // quando decodificados. Aqui estamos verificando se começa com eyJ (base64 de '{')
    // e termina com caracteres válidos geralmente encontrados em JWTs
    if !strings.HasPrefix(parts[0], "eyJ") || 
       !regexp.MustCompile(`[A-Za-z0-9_\-]+[=]{0,2}$`).MatchString(parts[2]) {
        return false
    }
    
    return true
}

// IsInMinifiedCode verifica se um valor está em contexto de código minificado
func IsInMinifiedCode(value, context string) bool {
    // Código minificado geralmente tem poucas quebras de linha
    if len(context) > 100 && strings.Count(context, "\n") < 3 {
        return true
    }
    
    // Muitos operadores sem espaço entre eles
    operatorCount := 0
    operatorPatterns := []string{
        "++", "--", "+=", "-=", "*=", "/=", 
        "==", "===", "!=", "!==", ">=", "<=",
        "&&", "||", ">>", "<<", ">>>", "<<=",
    }
    
    for _, op := range operatorPatterns {
        operatorCount += strings.Count(context, op)
    }
    
    // Se houver muitos operadores, provavelmente é código minificado
    if operatorCount > 5 {
        return true
    }
    
    // Padrões de código minificado: variáveis de uma letra, funcões anônimas, etc.
    minifiedPatterns := []string{
        ";var ", ";let ", ";const ", ";function", 
        "function(", "return ", "+function",
        "}(", "({", "})", ":[", ",function", 
        "=[", "={", "=function",
    }
    
    patternCount := 0
    for _, pattern := range minifiedPatterns {
        if strings.Contains(context, pattern) {
            patternCount++
        }
    }
    
    // Se encontrarmos vários padrões, é muito provavelmente código minificado
    return patternCount >= 3
}

// IsBase64StringFragment verifica se um valor que começa com "eyJ" é na verdade um fragmento 
// de uma string base64 maior (como em dados minificados) e não um token JWT
func IsBase64StringFragment(value, context string) bool {
    // Base64 sem pontos não pode ser JWT válido
    if !strings.Contains(value, ".") {
        return true
    }
    
    // Se é muito curto para um JWT válido
    if len(value) < 30 {
        return true
    }
    
    // Verifica padrões de embasamento de JWT não válidos
    parts := strings.Split(value, ".")
    if len(parts) != 3 {
        return true
    }
    
    // Verifica se o contexto contém fragmentos longos de base64 (common in minified code)
    base64Fragments := regexp.MustCompile(`[A-Za-z0-9+/]{30,}={0,2}`).FindAllString(context, -1)
    
    if len(base64Fragments) > 0 {
        // Verifica se nosso valor é parte de um fragmento maior
        for _, fragment := range base64Fragments {
            if len(fragment) > len(value) && strings.Contains(fragment, value) {
                // O valor é parte de um fragmento base64 maior
                return true
            }
        }
    }
    
    // Verifica se faz parte de uma string maior de código
    // Isto é comum em código minificado onde strings longas aparecem
    beforeAfterLength := 15 // Examine 15 caracteres antes e depois
    valuePos := strings.Index(context, value)
    
    if valuePos >= 0 {
        // Calcula a posição segura para início e fim
        startPos := max(0, valuePos-beforeAfterLength)
        endPos := min(len(context), valuePos+len(value)+beforeAfterLength)
        
        surrounding := context[startPos:endPos]
        
        // Verifica padrões comuns de literais de string em JS
        stringPatterns := []string{
            // Padrões de strings de código - variáveis, strings, objetos JSON
            "'", "\"", "+", "=", ":",  // Operadores de string e atribuição
            "{", "}", "[", "]",        // Objetos e arrays
            "var ", "let ", "const ",  // Declaração de variáveis
        }
        
        matchCount := 0
        for _, pattern := range stringPatterns {
            if strings.Contains(surrounding, pattern) {
                matchCount++
            }
        }
        
        // Se há vários desses padrões ao redor, é provavelmente código e não um token real
        if matchCount >= 3 {
            return true
        }
    }
    
    // Verifica características de origem trial e outras meta tags
    if strings.Contains(context, "content=") || strings.Contains(context, "origin") || 
       strings.Contains(context, "feature") || strings.Contains(context, "recaptcha") {
        return true
    }
    
    // Verifica por padrões de código minificado
    if IsInMinifiedCode(value, context) {
        // Em código minificado, precisamos de evidência forte de que é um JWT real
        // Se não encontrar indicadores explícitos de autenticação, assumir que é código
        authIndicators := []string{
            "token", "jwt", "auth", "login", "user", "session", "claim",
            "authorization", "authenticate", "identity", "credential", "bearer",
        }
        
        hasAuthIndicator := false
        for _, indicator := range authIndicators {
            if strings.Contains(strings.ToLower(context), indicator) {
                hasAuthIndicator = true
                break
            }
        }
        
        if !hasAuthIndicator {
            return true
        }
    }
    
    return false
}

// IsLongBase64InJSCode verifica se uma string parece ser parte de código JavaScript com dados base64
func IsLongBase64InJSCode(value, context string) bool {
    // Número mínimo de caracteres para considerar como uma string longa
    if len(value) < 40 {
        return false
    }
    
    // Verifique se contém caracteres base64 válidos mas nada mais
    if !regexp.MustCompile(`^[A-Za-z0-9+/=]+$`).MatchString(value) {
        return false
    }
    
    // Verifique padrões de código JavaScript
    jsCodePatterns := []string{
        // Operadores e sintaxe JS
        "function", "return", "var ", "let ", "const ", "=>", 
        "true", "false", "null", "undefined",
        "+", "=", ";", "{", "}", "[", "]", 
        
        // Padrões de uso de dados
        "base64", "encode", "decode", "JSON", "data:",
        "toString", "btoa", "atob", "charAt", 
        
        // Padrões de minificação
        ".min.js", "bundle", "webpack", "rollup", "terser",
    }
    
    patternMatches := 0
    for _, pattern := range jsCodePatterns {
        if strings.Contains(context, pattern) {
            patternMatches++
            if patternMatches >= 3 {
                return true
            }
        }
    }
    
    return false
}

