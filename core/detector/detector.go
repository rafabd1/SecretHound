package detector

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/secret"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

// Config holds detector configuration
type Config struct {
	// Whether to enable local file mode (less strict validation)
	LocalFileMode bool
	
	// Minimum confidence threshold (0.0-1.0)
	MinConfidence float64
	
	// Context size for extracting surrounding content
	ContextSize int
	
	// Treat test/example files less strictly
	AllowTestExamples bool
}

// Detector is responsible for detecting secrets in content
type Detector struct {
	patternManager *patterns.PatternManager
	logger         *output.Logger
	config         Config
	mu             sync.Mutex
	stats          Stats
}

// Stats tracks detector statistics
type Stats struct {
	ContentProcessed int
	SecretsFound     int
	ProcessingErrors int
}

// NewDetector creates a new detector
func NewDetector(patternManager *patterns.PatternManager, logger *output.Logger, config Config) *Detector {
	// Set default values if not provided
	if config.ContextSize == 0 {
		config.ContextSize = 100
	}
	
	if config.MinConfidence == 0 {
		config.MinConfidence = 0.5
	}
	
	return &Detector{
		patternManager: patternManager,
		logger:         logger,
		config:         config,
		stats:          Stats{},
	}
}

// DetectSecrets detects secrets in content
func (d *Detector) DetectSecrets(content, url string) ([]secret.Secret, error) {
	d.mu.Lock()
	d.stats.ContentProcessed++
	d.mu.Unlock()
	
	// Update pattern manager local mode
	d.patternManager.SetLocalMode(d.config.LocalFileMode)
	
	// Get all compiled patterns
	patterns := d.patternManager.GetCompiledPatterns()
	
	// Use fallback detector se não houver padrões ou se ocorrer um erro grave
	if (len(patterns) == 0) {
		// Cria um detector de fallback
		fallback := NewFallbackDetector()
		secrets := fallback.DetectWithFallback(content, url)
		
		if len(secrets) > 0 {
			d.logger.Warning("Using fallback detection mode - limited patterns available")
			
			// Atualiza estatísticas
			d.mu.Lock()
			d.stats.SecretsFound += len(secrets)
			d.mu.Unlock()
			
			return secrets, nil
		}
	}
	
	// Track detected secrets
	var secrets []secret.Secret
	
	// Check content for test/example indicators
	isExampleContent := d.isExampleContent(content)
	
	// Find secrets using each pattern
	for _, pattern := range patterns {
		// Find all matches
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			
			// Get the capture group if available, otherwise use the full match
			value := match[0]
			if len(match) > 1 && match[1] != "" {
				value = match[1]
			}
			
			// Get context around the match
			ctx := secret.ExtractContext(content, value, d.config.ContextSize)
			
			// Calculate line number
			line := utils.FindLineNumber(content, value)
			
			// Validate the secret according to mode
			valid, confidence := d.validateSecret(pattern.Name, value, ctx, isExampleContent)
			
			if valid && confidence >= d.config.MinConfidence {
				// Create the secret
				s := secret.NewSecret(pattern.Name, value, ctx, url, line)
				s.Confidence = confidence
				s.Description = pattern.Description
				
				secrets = append(secrets, s)
			}
		}
	}
	
	// Use o fallback detector se ocorrer um erro grave
	if len(secrets) == 0 && d.stats.ProcessingErrors > 5 {
		// Se estamos encontrando muitos erros, tente o fallback
		fallback := NewFallbackDetector() 
		fallbackSecrets := fallback.DetectWithFallback(content, url)
		
		if len(fallbackSecrets) > 0 {
			d.logger.Warning("Detection errors detected - using fallback patterns")
			secrets = fallbackSecrets
		}
	}
	
	// Update stats
	d.mu.Lock()
	d.stats.SecretsFound += len(secrets)
	d.mu.Unlock()
	
	return secrets, nil
}

// isExampleContent checks if content appears to be test/example content
func (d *Detector) isExampleContent(content string) bool {
	// Keywords that indicate example/test content
	exampleKeywords := []string{
		"example", "EXAMPLE", "sample", "SAMPLE", "test", "TEST",
		"DO NOT COMMIT", "do not commit", "don't commit", "demo", "DEMO",
	}
	
	// Check for the presence of any keyword
	for _, keyword := range exampleKeywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	
	return false
}

// validateSecret valida se um potencial segredo é válido
func (d *Detector) validateSecret(
    patternName, value, context string, 
    isExampleContent bool,
) (bool, float64) {
    // Get the pattern config
    patterns := d.patternManager.GetCompiledPatterns()
    pattern, exists := patterns[patternName]
    if !exists {
        return false, 0
    }
    
    config := pattern.Config
    
    // Always validate against length
    if len(value) < config.MinLength {
        return false, 0
    }
    
    if config.MaxLength > 0 && len(value) > config.MaxLength {
        return false, 0
    }
    
    // Example content handling
    if isExampleContent && !d.config.AllowTestExamples {
        return false, 0
    }
    
    // JavaScript specific validations
    if utils.IsJavaScriptFunction(value) || utils.IsJavaScriptConstant(value) || 
       utils.HasJavaScriptCamelCasePattern(value) {
        return false, 0
    }
    
    // Check if matches exclusion keywords
    for _, keyword := range config.KeywordExcludes {
        if strings.Contains(value, keyword) || strings.Contains(context, keyword) {
            return false, 0
        }
    }
    
    // Common false positive checks
    if utils.IsLikelyCSS(value) ||
       utils.IsLikelyI18nKey(value) ||
       utils.HasRepeatedCharacterPattern(value) ||
       utils.IsLikelyFunctionName(value) ||
       utils.IsLikelyDocumentation(value, context) ||
       utils.IsLikelyUrl(value) ||
       utils.IsUUID(value) {
        return false, 0
    }
    
    // NOVOS VALIDADORES PARA REDUZIR FALSOS POSITIVOS
    
    // Validações específicas por tipo de segredo
    switch patternName {
    case "jwt_token":
        // Verificar se parece ser um token de Origin Trial (comum em scripts do Google)
        if utils.IsLikelyOriginTrialToken(value, context) {
            return false, 0
        }
        
        // Verifica se é realmente um token JWT válido
        if !utils.IsValidJWTToken(value) {
            return false, 0
        }
        
        // Verifica se é apenas um fragmento de uma string base64 maior ou parte de código JS
        if utils.IsBase64StringFragment(value, context) || utils.IsLongBase64InJSCode(value, context) {
            return false, 0
        }
        
        // Verifica se está em código minificado sem outros indícios de ser um token real
        if utils.IsInMinifiedCode(value, context) && !hasStrongJWTIndicators(value, context) {
            return false, 0
        }
        
        // Caso seja detectado como string longa de base64 em código JS
        if utils.IsLikelyBase64Data(value) && !hasStrongAuthContext(context) {
            return false, 0
        }
        
    case "oauth_token":
        // Verificar se é apenas uma referência de variável em código
        if utils.IsVariableReference(value, context) {
            return false, 0
        }
        
    case "basic_auth":
        // Verificar se é um cabeçalho ou título de UI (como "Basic authorization")
        if utils.IsUIHeaderOrTitle(value, context) {
            return false, 0
        }
        
        // Verificar se é uma referência a Unicode Basic Multilingual Plane (BMP)
        if utils.IsUnicodeReference(value, context) || 
           strings.Contains(value, "Basic Multilingual") {
            return false, 0
        }
        
        // Verificar Basic Auth em contexto de documentação
        if utils.IsLikelyBasicAuthSyntax(value, context) {
            return false, 0
        }
        
    case "generic_password":
        // Verificar se é texto de UI/label em vez de senha real
        if utils.IsUITextOrLabel(value, context) {
            return false, 0
        }
        
        // Verificar se é um seletor DOM ou pseudo-elemento (como input[type="password"])
        if utils.IsDOMSelectorOrPseudo(value, context) {
            return false, 0
        }
        
    case "firebase_api_key":
        // Verificar se é uma API key do Google Fonts (menos sensível)
        if utils.IsGoogleFontApiKey(value, context) {
            return false, 0
        }
    }
    
    // Check if context indicates minified JavaScript code
    if utils.IsLikelyMinifiedCode(context) {
        // More strict validation for minified code to reduce false positives
        if !hasStrongSecretIndicators(value, context) {
            return false, 0
        }
    }
    
    // Calculate confidence based on pattern-specific factors
    confidence := calculateConfidence(patternName, value, context)
    
    // Local file mode adjustment
    if d.config.LocalFileMode {
        confidence += 0.1
    }
    
    return true, confidence
}

// hasStrongSecretIndicators verifica se há fortes indicadores de que o valor é um segredo
func hasStrongSecretIndicators(value, context string) bool {
	// Verifica a presença de prefixos de token comuns
	tokenPrefixes := []string{
		"sk_", "pk_", "ghp_", "ya29.", "gho_", "AKIA", "xox",
	}
	
	for _, prefix := range tokenPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	
	// Verifica a presença de palavras-chave de segurança no contexto próximo
	securityKeywords := []string{
		"api_key", "apiKey", "secret", "token", "password", "credential",
		"authorization", "auth_token", "secret_key", "private_key",
	}
	
	contextLower := strings.ToLower(context)
	for _, keyword := range securityKeywords {
		if strings.Contains(contextLower, keyword) {
			return true
		}
	}
	
	// Verifica por padrões de atribuição de variáveis
	assignmentPatterns := []string{
		`const\s+\w+\s*=\s*['"]`,
		`let\s+\w+\s*=\s*['"]`,
		`var\s+\w+\s*=\s*['"]`,
		`:\s*['"]`,
		`=\s*['"]`,
	}
	
	for _, pattern := range assignmentPatterns {
		if regexp.MustCompile(pattern).MatchString(context) {
			// Verifica se o valor tem alta entropia e não parece código
			if utils.CalculateEntropy(value) > 4.0 && !utils.HasCommonCodePattern(value) {
				return true
			}
		}
	}
	
	return false
}

// hasStrongJWTIndicators verifica se há indicadores fortes de que um JWT token é real
func hasStrongJWTIndicators(value, context string) bool {
    // Tokens JWT válidos têm 3 partes separadas por pontos
    parts := strings.Split(value, ".")
    if len(parts) != 3 {
        return false
    }
    
    // Verifica a presença de palavras-chave relacionadas a autenticação no contexto
    authKeywords := []string{
        "token", "jwt", "auth", "authorization", "authentication", 
        "login", "session", "identity", "credential", "bearer",
        "user", "account", "profile", "secure", "access",
    }
    
    contextLower := strings.ToLower(context)
    keywordCount := 0
    
    for _, keyword := range authKeywords {
        if strings.Contains(contextLower, keyword) {
            keywordCount++
            // Se encontrar pelo menos 2 palavras-chave diferentes relacionadas a autenticação
            if keywordCount >= 2 {
                return true
            }
        }
    }
    
    // Verifica por padrões de atribuição que indicam uso de token
    assignmentPatterns := []string{
        "token", "jwt", "idToken", "accessToken", "auth",
    }
    
    for _, pattern := range assignmentPatterns {
        if regexp.MustCompile(fmt.Sprintf(`['"]?%s['"]?\s*[=:]\s*['"]`, pattern)).MatchString(contextLower) {
            return true
        }
    }
    
    // Verificar se a estrutura do JWT parece ser válida (header, payload, signature)
    // Um JWT válido tem três partes e cada uma é decodificável como base64
    if len(parts) == 3 && strings.HasPrefix(parts[0], "eyJ") {
        // Se o token parece estruturalmente válido, é mais provável que seja real
        if len(parts[1]) > 20 && len(parts[2]) > 16 {
            return true
        }
    }
    
    return false
}

// hasStrongAuthContext verifica se o contexto indica realmente autenticação
func hasStrongAuthContext(context string) bool {
    // Palavras fortemente associadas com autenticação
    strongAuthWords := []string{
        "authentication", "authorization", "credentials", "login", 
        "session", "identity", "user", "account", "password",
        "oauth", "openid", "saml", "permission", "access",
    }
    
    contextLower := strings.ToLower(context)
    matchCount := 0
    
    for _, word := range strongAuthWords {
        if strings.Contains(contextLower, word) {
            matchCount++
            if matchCount >= 2 {
                return true
            }
        }
    }
    
    return false
}

// hasSecretContext checks if the context looks like it might contain a secret
func hasSecretContext(context string) bool {
    secretContexts := []string{
        "key", "token", "secret", "password", "credential", "auth",
        "apikey", "api_key", "authorization", "private", "access",
    }
    
    lowerContext := strings.ToLower(context)
    for _, secretWord := range secretContexts {
        if strings.Contains(lowerContext, secretWord) {
            return true
        }
    }
    
    return false
}

// hasCodePattern checks if a string contains patterns that indicate it's part of code
func hasCodePattern(s string) bool {
	codePatterns := []string{
		"function", "return", "const ", "var ", "let ",
		"import ", "export ", "require(", "module.", "class ",
		"window.", "document.", "querySelector", "getElementById",
	}
	
	for _, pattern := range codePatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	
	return false
}

// containsCommonFalsePositive checks if a string contains common false positive patterns
func containsCommonFalsePositive(s string) bool {
	falsePositives := []string{
		"example", "sample", "test", "placeholder", "dummy",
		"http://", "https://", "localhost", "127.0.0.1",
		"node_modules", "charset=", "@example.com", 
		"--", "css", "style", "font", "color", "background",
		"format", "message", "label", "text", "caption",
	}
	
	for _, pattern := range falsePositives {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	
	return false
}

// calculateConfidence calculates confidence for a potential secret
func calculateConfidence(patternName, value, context string) float64 {
	// Start with moderate confidence
	confidence := 0.6
	
	// Adjust based on the type of secret
	switch {
	case strings.Contains(patternName, "aws") && strings.HasPrefix(value, "AKIA"):
		confidence += 0.3 // AWS keys are distinctive
	
	case strings.Contains(patternName, "google_api") && strings.HasPrefix(value, "AIza"):
		confidence += 0.3 // Google API keys are distinctive
		
	case strings.Contains(patternName, "stripe") && 
		 (strings.HasPrefix(value, "sk_live_") || strings.HasPrefix(value, "pk_live_")):
		confidence += 0.3 // Stripe keys are distinctive
		
	case strings.Contains(patternName, "twilio") && strings.HasPrefix(value, "AC"):
		confidence += 0.3 // Twilio keys are distinctive
		
	case strings.Contains(patternName, "jwt") && strings.HasPrefix(value, "eyJ"):
		confidence += 0.2 // JWT tokens are fairly distinctive
		
	case strings.Contains(patternName, "high_entropy"):
		// For high entropy strings, check character distribution
		// We use a simple metric instead of full entropy calculation
		uniqueChars := countUniqueChars(value)
		if float64(uniqueChars)/float64(len(value)) > 0.5 {
			confidence += 0.1 // String has high unique character ratio
		}
		
	case strings.Contains(patternName, "generic_password"):
		// For generic passwords, be more cautious
		confidence -= 0.1
	}
	
	// Check for specific key/value assignment patterns that indicate real configs
	keyValuePatterns := []string{
		"apiKey", "api_key", "apikey", "token", "secret", "password",
		"credential", "auth", "key", "access",
	}
	
	for _, pattern := range keyValuePatterns {
		if strings.Contains(strings.ToLower(context), pattern) {
			confidence += 0.1
			break
		}
	}
	
	// Limit confidence to range [0.0, 1.0]
	if confidence < 0 {
		confidence = 0
	} else if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// countUniqueChars counts the number of unique characters in a string
func countUniqueChars(s string) int {
	charSet := make(map[rune]struct{})
	for _, r := range s {
		charSet[r] = struct{}{}
	}
	return len(charSet)
}

// GetStats returns detector statistics
func (d *Detector) GetStats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	return d.stats
}

// Reset resets the detector
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.stats = Stats{}
}

// SetConfig updates the detector configuration
func (d *Detector) SetConfig(config Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.config = config
}
