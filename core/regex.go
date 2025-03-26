package core

import (
    "bufio"
    "fmt"
    "os"
    "regexp"
    "strings"
    "sync"

    "github.com/secrethound/utils"
)

// RegexManager handles loading and applying regex patterns
type RegexManager struct {
    patterns           map[string]*regexp.Regexp
    exclusionPatterns  []*regexp.Regexp       // Padrões para filtrar falsos positivos
    patternExclusions  map[string][]*regexp.Regexp // Exclusões específicas por padrão
    excludedExtensions []string               // Extensões de arquivo para ignorar
    minSecretLength    int                    // Tamanho mínimo para considerar um segredo
    maxSecretLength    int                    // Tamanho máximo para considerar um segredo
    mu                 sync.RWMutex
}

// NewRegexManager creates a new regex manager
func NewRegexManager() *RegexManager {
    return &RegexManager{
        patterns:           make(map[string]*regexp.Regexp),
        exclusionPatterns:  make([]*regexp.Regexp, 0),
        excludedExtensions: []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"},
        minSecretLength:    5,   // Mínimo de 5 caracteres para considerar um segredo
        maxSecretLength:    200, // Máximo de 200 caracteres para evitar blocos de código inteiros
        mu:                 sync.RWMutex{},
    }
}

// FindSecrets busca segredos usando as expressões regulares configuradas
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    return rm.findSecretsWithFiltering(content, url, false)
}

// FindSecretsWithStrictFiltering é uma versão da FindSecrets que aplica filtros mais rígidos para conteúdo minificado
func (rm *RegexManager) FindSecretsWithStrictFiltering(content, url string) ([]Secret, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    return rm.findSecretsWithFiltering(content, url, true)
}

// findSecretsWithFiltering é a implementação central de busca de segredos com filtragem opcional
func (rm *RegexManager) findSecretsWithFiltering(content, url string, strictMode bool) ([]Secret, error) {
    if len(rm.patterns) == 0 {
        return nil, fmt.Errorf("no regex patterns loaded")
    }

    // Verificar extensões de arquivo a serem ignoradas
    for _, ext := range rm.excludedExtensions {
        if strings.HasSuffix(strings.ToLower(url), ext) {
            return nil, nil
        }
    }

    var secrets []Secret
    
    // Para cada padrão, buscar no conteúdo
    for patternName, pattern := range rm.patterns {
        matches := pattern.FindAllStringSubmatch(content, -1)
        
        for _, match := range matches {
            if len(match) > 0 {
                // Extrair o valor real do segredo (primeiro grupo de captura ou match completo)
                value := match[0]
                if len(match) > 1 && match[1] != "" {
                    value = match[1]
                }
                
                // Aplicar verificações básicas ou estritas dependendo do modo
                isValid := false
                if strictMode {
                    isValid = rm.isValidSecretStrict(value, patternName)
                } else {
                    isValid = rm.isValidSecret(value, patternName)
                }
                
                if isValid {
                    // Obter contexto ao redor do segredo (opcional)
                    context := rm.extractContext(content, value)
                    
                    // Aplicar verificações de contexto
                    isExcluded := false
                    if strictMode {
                        isExcluded = rm.isExcludedByContextStrict(context, patternName)
                    } else {
                        isExcluded = rm.isExcludedByContext(context)
                    }
                    
                    if !isExcluded {
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
        }
    }
    
    return secrets, nil
}

// extractContext extrai o contexto ao redor do segredo
func (rm *RegexManager) extractContext(content, value string) string {
    idx := strings.Index(content, value)
    if idx == -1 {
        return ""
    }
    
    // Extrair 50 caracteres antes e depois do segredo
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

// isExcludedByContext verifica se o contexto indica que o match deve ser ignorado
func (rm *RegexManager) isExcludedByContext(context string) bool {
    // Verificar padrões de exclusão global
    for _, pattern := range rm.exclusionPatterns {
        if pattern.MatchString(context) {
            return true
        }
    }
    
    return false
}

// isValidSecret verifica se o valor encontrado parece ser um segredo válido
func (rm *RegexManager) isValidSecret(value string, patternType string) bool {
	// Verificar tamanho mínimo e máximo
	if len(value) < rm.minSecretLength || len(value) > rm.maxSecretLength {
		return false
	}
	
	// Verificações específicas por tipo de padrão
	switch {
	case strings.Contains(patternType, "twilio_account_sid"):
		// Verificar se começa com AC e não está em um contexto de CSS ou base64
		if !strings.HasPrefix(value, "AC") || 
			strings.Contains(value, "AAA") || 
			strings.Contains(value, "eJy") {
			return false
		}
		
		// Verificar se não está em um contexto provável de CSS/estilos
		styleKeywords := []string{"width", "height", "margin", "padding", "content"}
		for _, keyword := range styleKeywords {
			if strings.Contains(value, keyword) {
				return false
			}
		}
		
	case strings.Contains(patternType, "twilio_app_sid"):
		// Verificar se começa com AP e não está em um contexto de CSS ou base64
		if !strings.HasPrefix(value, "AP") || 
			strings.Contains(value, "AAA") || 
			strings.Contains(value, "eJy") {
			return false
		}
		
		// Verificar se não está em um contexto provável de CSS/estilos
		styleKeywords := []string{"width", "height", "margin", "padding", "content"}
		for _, keyword := range styleKeywords {
			if strings.Contains(value, keyword) {
				return false
			}
		}
		
	case strings.Contains(patternType, "Heroku API KEY") || 
		strings.Contains(patternType, "heroku"):
		// Verificar se está em um contexto de configuração de interface
		uiContextKeywords := []string{"id:", "target", "element", "styleBlock", "applies"}
		for _, keyword := range uiContextKeywords {
			if strings.Contains(value, keyword) {
				return false
			}
		}
		
		// Verificar se tem um prefixo ou contexto que indique que é uma chave Heroku
		if !strings.Contains(strings.ToLower(value), "heroku") && 
			!strings.Contains(strings.ToLower(value), "api") && 
			!strings.Contains(strings.ToLower(value), "key") {
			// Se não tem nenhuma indicação de ser Heroku no contexto, provavelmente é UUID comum
			return false
		}
		
	case strings.Contains(patternType, "aws_url") || strings.Contains(patternType, "s3"):
		// Evitar falsos positivos para URLs do Amazon S3
		if strings.Contains(value, "TR/css3-selectors") {
			return false
		}
		if strings.Contains(value, "TR/2011/REC-css3-selectors") {
			return false
		}
		
	case strings.Contains(patternType, "base64") || strings.Contains(patternType, "token"):
		// Para tokens, verificar se parece com código minificado
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

// LoadPatternsFromFile loads regex patterns from a file
func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
    // First check if the file exists
    if !utils.FileExists(filePath) {
        return fmt.Errorf("regex file not found: %s", filePath)
    }

    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("failed to open regex file: %v", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var inPatternSection bool

    // Create a temporary map to avoid partial updates in case of errors
    tempPatterns := make(map[string]*regexp.Regexp)

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())

        // Skip empty lines and comments
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        // Check for the start of the pattern section
        if strings.HasPrefix(line, "REGEX_PATTERNS = {") {
            inPatternSection = true
            continue
        }

        // Check for the end of the pattern section
        if line == "}" {
            break
        }

        // Process pattern lines
        if inPatternSection {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) != 2 {
                continue
            }

            // Extract pattern name and regex
            patternName := strings.Trim(parts[0], " '\",")
            patternRegex := strings.Trim(parts[1], " '\",")

            // Remove trailing comma if present
            patternRegex = strings.TrimSuffix(patternRegex, ",")

            // Compile regex
            re, err := regexp.Compile(patternRegex)
            if err != nil {
                return fmt.Errorf("failed to compile regex '%s': %v", patternName, err)
            }

            tempPatterns[patternName] = re
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("error reading regex file: %v", err)
    }

    if len(tempPatterns) == 0 {
        return fmt.Errorf("no regex patterns found in file")
    }

    // Update the patterns map atomically
    rm.mu.Lock()
    rm.patterns = tempPatterns
    rm.mu.Unlock()

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