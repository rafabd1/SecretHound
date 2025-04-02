package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

// Processor is responsible for processing JS files and extracting secrets
type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
	cacheService *CacheService
	mu           sync.Mutex
	stats        ProcessorStats
}

// ProcessorStats tracks statistics about the processing
type ProcessorStats struct {
	FilesProcessed  int
	SecretsFound    int
	ProcessingTime  time.Duration
	FailedFiles     int
	TotalBytesRead  int64
}

// NewProcessor creates a new processor instance
func NewProcessor(regexManager *RegexManager, logger *output.Logger) *Processor {
	processor := &Processor{
		regexManager: regexManager,
		logger:       logger,
		cacheService: NewCacheService(),
		stats: ProcessorStats{
			FilesProcessed: 0,
			SecretsFound:   0,
		},
	}
	
	// Register this processor globally so it can be reset if needed
	RegisterProcessor(processor)
	
	return processor
}

// InitializeRegexManager ensures that RegexManager has patterns loaded
func (p *Processor) InitializeRegexManager() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Always create a fresh instance
    p.regexManager = NewRegexManager()
    
    // Para diagnóstico, injetar os padrões diretamente
    p.regexManager.InjectDefaultPatternsDirectly()
    fmt.Printf("DEBUG: Injetados padrões diretamente. RegexManager tem %d padrões.\n",
              p.regexManager.GetPatternCount())
    
    /*
    // O método normal de carregamento pode estar causando problemas
    err := p.regexManager.LoadPredefinedPatterns()
    if err != nil {
        return fmt.Errorf("failed to load predefined patterns: %w", err)
    }
    */
    
    return nil
}

// ProcessJSContent processes JavaScript content and extracts secrets
func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
    // Forçar inicialização do RegexManager a cada execução para diagnóstico
    fmt.Println("DEBUG: Forçando inicialização do RegexManager")
    err := p.InitializeRegexManager()
    if err != nil {
        fmt.Println("ERRO FATAL: Falha ao inicializar RegexManager:", err)
        return nil, fmt.Errorf("falha na inicialização: %w", err)
    }
    
    patternCount := p.regexManager.GetPatternCount()
    fmt.Printf("DEBUG: RegexManager inicializado com %d padrões\n", patternCount)
    
    // Desabilitar qualquer cache para diagnóstico
    startTime := time.Now()

    // Use the regex manager to find secrets in the content
    var secrets []Secret
    
    // Usar versão não-estrita para diagnóstico
    secrets, err = p.regexManager.FindSecrets(content, url)
    
    if err != nil {
        fmt.Println("ERRO: Falha ao encontrar segredos:", err)
        return nil, err
    }
    
    fmt.Printf("DEBUG: Encontrados %d segredos brutos em %s\n", len(secrets), url)
    
    // DIAGNÓSTICO: Pular todo o filtro adicional para ver o que está acontecendo
    filteredSecrets := secrets
    
    // Para diagnóstico, imprimir os primeiros 5 segredos encontrados
    count := 0
    for _, s := range filteredSecrets {
        if count < 5 {
            valuePreview := s.Value
            if len(valuePreview) > 20 {
                valuePreview = valuePreview[:20] + "..."
            }
            fmt.Printf("DEBUG: Segredo #%d: Tipo=%s, Valor=%s\n", 
                      count+1, s.Type, valuePreview)
            count++
        }
    }

    // Update stats
    p.mu.Lock()
    p.stats.FilesProcessed++
    p.stats.SecretsFound += len(filteredSecrets)
    p.stats.TotalBytesRead += int64(len(content))
    p.stats.ProcessingTime += time.Since(startTime)
    p.mu.Unlock()

    return filteredSecrets, nil
}

// updateStats updates processor statistics in a thread-safe way
func (p *Processor) updateStats(secretsFound int, contentSize int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.stats.FilesProcessed++
	p.stats.SecretsFound += secretsFound
	p.stats.TotalBytesRead += int64(contentSize)
}

// filterFalsePositives applies additional filtering to remove false positives
// Compiled regex patterns used for filtering false positives
var (
	testTokenPattern      = regexp.MustCompile(`(?i)(test|example|sample|dummy|demo)_?(token|key|secret)`)
	testTokenValuePattern = regexp.MustCompile(`(?i)(test|example|sample|dummy|demo)_?(token|key|secret)`)
)

func (p *Processor) filterFalsePositives(secrets []Secret) []Secret {
	// Create a map to keep track of unique values to avoid duplicates
	uniqueSecrets := make(map[string]Secret)

	falsePositiveIndicators := []string{
		"function", "return", "var ", "let ", "const ", "if ", "else ", "for ", "while ",
		"!0", "!1", "null", "undefined", "NaN", "Infinity",
		"checkbox", "radio", "input", "button", "select", "option",
		"jQuery", "React", "Vue", "Angular",
		"data:image", "data:font", "data:text",
		"charset", "unicode", "selector", "whitespace",
		"target", "element", "styleBlock", "appliesTo", "id:",
		"width", "height", "margin", "padding", "content:",
		"eJy", "AAA", "base64",
	}

	// Map of required context keywords for specific secret types
	requiredContextKeywords := map[string][]string{
		"twilio_account_sid": {"Twilio", "twilio", "account", "sid", "auth", "token"},
		"twilio_app_sid":     {"Twilio", "twilio", "app", "application", "sid", "auth"},
		"Heroku API KEY":     {"Heroku", "heroku", "HEROKU", "api", "key", "token", "auth", "secret"},
	}

	// Process specific pattern types first (non-high_entropy_string)
	for _, secret := range secrets {
		if secret.Type != "high_entropy_string" {
			// Apply regular filtering for non-high_entropy_string patterns
			isValid := true

			// Check if it is base64 and likely not a secret
			if utils.IsBase64Encoded(secret.Value) && !utils.IsLikelySecretInBase64(secret.Value) {
				isValid = false
			}

			// Check if the content appears to be a Base64 fragment
			if utils.IsLikelyBase64Fragment(secret.Value) {
				isValid = false
			}

			// Check for false positive indicators in the context
			for _, indicator := range falsePositiveIndicators {
				if strings.Contains(strings.ToLower(secret.Context), indicator) {
					isValid = false
					break
				}
			}

			// For certain types of secrets, check if the context contains required keywords
			if required, exists := requiredContextKeywords[secret.Type]; exists {
				hasRequiredKeyword := false
				for _, keyword := range required {
					if strings.Contains(strings.ToLower(secret.Context), keyword) {
						hasRequiredKeyword = true
						break
					}
				}

				// If no required keyword is found, it is likely a false positive
				if !hasRequiredKeyword {
					isValid = false
				}
			}

			// Check specific format for credentials
			if strings.Contains(secret.Type, "password") || strings.Contains(secret.Type, "credentials") {
				// Common false credentials like password:true, password:!0, etc.
				if strings.Contains(secret.Context, "password:true") ||
					strings.Contains(secret.Context, "password:!0") ||
					strings.Contains(secret.Context, "password:null") {
					isValid = false
				}
			}

			// Check if it looks like a JavaScript module header
			if strings.Contains(secret.Type, "aws") && strings.Contains(secret.Context, "w3.org/TR") {
				isValid = false
			}

			// Specific rules for UUID in contexts unrelated to secrets
			if strings.Contains(secret.Type, "Heroku") || strings.Contains(secret.Type, "UUID") {
				uiContextKeywords := []string{"target", "element", "styleBlock", "id:", "appliesTo"}
				for _, keyword := range uiContextKeywords {
					if strings.Contains(secret.Context, keyword) {
						isValid = false
						break
					}
				}
			}

			if isValid {
				// Use the value as the key to prevent duplicates
				uniqueSecrets[secret.Value] = secret
			}
		}
	}

	// Now process high_entropy_string patterns, but only if the value isn't already captured
	for _, secret := range secrets {
		if secret.Type == "high_entropy_string" {
			// Skip if we already have this value from a more specific pattern
			if _, exists := uniqueSecrets[secret.Value]; exists {
				continue
			}

			// Apply stricter filtering for high_entropy_string
			isValid := true

			// Skip common programming patterns
			if isCommonProgrammingPattern(secret.Value) || isCommonProgrammingContext(secret.Context) {
				isValid = false
			}

			// Skip if it looks like encoded content but not a secret
			if utils.IsBase64Encoded(secret.Value) && !utils.IsLikelySecretInBase64(secret.Value) {
				isValid = false
			}

			// Skip common developer terms that might be long
			commonDevTerms := []string{
				"implementation", "configuration", "development", "production",
				"authorization", "authentication", "environment", "component",
				"serializer", "deserializer", "transformer", "stylesheet",
				"javascript", "typescript", "repository", "dependency",
			}

			for _, term := range commonDevTerms {
				if strings.Contains(strings.ToLower(secret.Value), term) {
					isValid = false
					break
				}
			}

			// Check if it matches common token formats with obvious names
			if testTokenPattern.MatchString(secret.Value) {
				isValid = false
			}
			// Check if it matches common token formats with obvious names
			if testTokenValuePattern.MatchString(secret.Value) {
				isValid = false
			}

			// Additional context checks for high entropy strings
			if !containsSecretIndicators(secret.Context) {
				isValid = false
			}

			if isValid {
				uniqueSecrets[secret.Value] = secret
			}
		}
	}

	// Convert map back to slice
	filtered := make([]Secret, 0, len(uniqueSecrets))
	for _, secret := range uniqueSecrets {
		filtered = append(filtered, secret)
	}

	return filtered
}

// isCommonProgrammingPattern checks if the string looks like code
func isCommonProgrammingPattern(value string) bool {
	codePatterns := []string{
		"function", "return", "var ", "let ", "const ",
		"if(", "else{", "for(", "while(", "switch",
		"class", "interface", "typeof", "instanceof",
		"import", "export", "require", "module",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range codePatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

// containsSecretIndicators checks if the context suggests this is a secret
func containsSecretIndicators(context string) bool {
	secretIndicators := []string{
		"api", "key", "token", "secret", "password", "credential",
		"auth", "secure", "private", "access", "sensitive",
		"confidential", "protected",
	}

	lowerContext := strings.ToLower(context)
	for _, indicator := range secretIndicators {
		if strings.Contains(lowerContext, indicator) {
			return true
		}
	}

	return false
}

// filterByContext checks if a potential secret is valid based on its context
func (p *Processor) filterByContext(secrets []Secret) []Secret {
	filtered := make([]Secret, 0, len(secrets))

	for _, secret := range secrets {
		// Skip secrets with common programming contexts
		if isCommonProgrammingContext(secret.Context) {
			continue
		}

		// Specific filter for authorization types
		if strings.Contains(secret.Type, "authorization") {
			if !isValidAuthorizationSecret(secret) {
				continue
			}
		}

		filtered = append(filtered, secret)
	}

	return filtered
}

// isCommonProgrammingContext checks if the context is typical of programming code
func isCommonProgrammingContext(context string) bool {
	// Code patterns
	codePatterns := []string{
		"function", "return", "var ", "let ", "const ",
		"if (", "else {", "for (", "while (", "switch",
		"class ", "interface ", "typeof ", "instanceof ",
		"import ", "export ", "require(",
	}

	lowerContext := strings.ToLower(context)
	for _, pattern := range codePatterns {
		if strings.Contains(lowerContext, pattern) {
			return true
		}
	}

	return false
}

// isValidAuthorizationSecret checks if an authorization secret is valid based on context
func isValidAuthorizationSecret(secret Secret) bool {
	// For authorization secrets, check for HTTP context which increases likelihood of real secret
	httpContextIndicators := []string{
		"headers", "authentication", "authorization", "credentials",
		"http", "https", "token", "login", "session", "oauth",
		"authenticated", "password", "username", "user", "account",
	}

	// Check for "proper" authorization_basic format (base64 of user:pass)
	if secret.Type == "authorization_basic" {
		parts := strings.SplitN(secret.Value, " ", 2)
		if len(parts) < 2 {
			return false
		}

		// Check if it contains a colon when decoded (username:password format)
		decodedBytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err == nil {
			decodedStr := string(decodedBytes)
			if strings.Contains(decodedStr, ":") {
				// This looks like a proper basic auth credential
				return true
			}
		}

		// Not a valid basic auth format, but might be valid if in HTTP context
		lowerContext := strings.ToLower(secret.Context)
		for _, indicator := range httpContextIndicators {
			if strings.Contains(lowerContext, indicator) {
				return true
			}
		}

		return false
	}

	// For API keys, check if the context suggests authentication
	if secret.Type == "authorization_api" {
		lowerContext := strings.ToLower(secret.Context)
		for _, indicator := range httpContextIndicators {
			if strings.Contains(lowerContext, indicator) {
				return true
			}
		}

		// Additional check for API keys
		apiKeyIndicators := []string{
			"apikey", "api_key", "api-key", "key", "secret", "token",
			"auth", "authenticate", "authorized",
		}

		for _, indicator := range apiKeyIndicators {
			if strings.Contains(lowerContext, indicator) {
				return true
			}
		}

		return false
	}

	return true
}

// ProcessJSStream processes a JavaScript content stream and extracts secrets
func (p *Processor) ProcessJSStream(ctx context.Context, reader io.Reader, url string) ([]Secret, error) {
	var builder strings.Builder
	buffer := make([]byte, 4096)

	for {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return nil, utils.NewError(utils.ProcessingError, "processing canceled", ctx.Err())
		default:
			// Continue processing
		}

		n, err := reader.Read(buffer)
		if n > 0 {
			builder.Write(buffer[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, utils.NewError(utils.ProcessingError, "error reading content stream", err)
		}
	}

	return p.ProcessJSContent(builder.String(), url)
}

// GetStats returns the current processor stats
func (p *Processor) GetStats() ProcessorStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.stats
}

// ResetStats resets the processor stats
func (p *Processor) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats = ProcessorStats{}
}

// CompleteReset completely resets the processor to a clean initial state
func (p *Processor) CompleteReset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Create a fresh RegexManager
	if p.regexManager != nil {
		p.regexManager.CompleteReset()
	}
	
	// Set a brand new RegexManager
	p.regexManager = NewRegexManager()
	
	// Reset the cache service
	p.cacheService = NewCacheService()
	
	// Reset stats
	p.stats = ProcessorStats{
		FilesProcessed: 0,
		SecretsFound:   0,
		ProcessingTime: 0,
		FailedFiles:    0,
		TotalBytesRead: 0,
	}
}

// BatchProcess processes multiple content strings in parallel
func (p *Processor) BatchProcess(contents map[string]string, concurrency int) (map[string][]Secret, error) {
	results := make(map[string][]Secret)
	resultsMu := sync.Mutex{}
	errors := make([]error, 0)
	errorsMu := sync.Mutex{}

	// Create a worker pool
	pool := utils.NewWorkerPool(concurrency, len(contents))

	// Add jobs to the pool
	for url, content := range contents {
		url := url     // Create local copy for closure
		content := content

		pool.Submit(func() (interface{}, error) {
			secrets, err := p.ProcessJSContent(content, url)
			if err != nil {
				return nil, err
			}

			return struct {
				URL     string
				Secrets []Secret
			}{
				URL:     url,
				Secrets: secrets,
			}, nil
		})
	}

	// Process results
	for result := range pool.Results() {
		r := result.(struct {
			URL     string
			Secrets []Secret
		})

		resultsMu.Lock()
		results[r.URL] = r.Secrets
		resultsMu.Unlock()
	}

	// Process errors
	for err := range pool.Errors() {
		errorsMu.Lock()
		errors = append(errors, err)
		errorsMu.Unlock()
	}

	// Wait for all jobs to complete
	pool.Wait()

	// If there were errors, return the first one
	if len(errors) > 0 {
		return results, errors[0]
	}

	return results, nil
}

// GetRegexPatternCount returns the count of regex patterns
func (p *Processor) GetRegexPatternCount() int {
	if p.regexManager != nil {
		return p.regexManager.GetPatternCount()
	}
	return 0
}

