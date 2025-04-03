package utils

import (
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
