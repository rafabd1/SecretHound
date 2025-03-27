package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/secrethound/output"
	"github.com/secrethound/utils"
)

// Processor is responsible for processing JS files and extracting secrets
type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
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
	return &Processor{
		regexManager: regexManager,
		logger:       logger,
		stats: ProcessorStats{
			FilesProcessed: 0,
			SecretsFound:   0,
		},
	}
}

// ProcessJSContent processes JavaScript content and extracts secrets
func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
	startTime := time.Now()
	p.logger.Debug("Processing content from URL: %s", url)
	
	// Update processor stats
	p.mu.Lock()
	p.stats.FilesProcessed++
	p.stats.TotalBytesRead += int64(len(content))
	p.mu.Unlock()
	
	isMinified := utils.IsMinifiedJavaScript(content)
	
	// Use the regex manager to find secrets in the content
	var secrets []Secret
	var err error
	
	if isMinified {
		p.logger.Debug("Content appears to be minified JavaScript, applying strict filters")
		secrets, err = p.regexManager.FindSecretsWithStrictFiltering(content, url)
	} else {
		secrets, err = p.regexManager.FindSecrets(content, url)
	}
	
	if err != nil {
		p.mu.Lock()
		p.stats.FailedFiles++
		p.mu.Unlock()
		return nil, utils.NewError(utils.ProcessingError, fmt.Sprintf("failed to process content from %s", url), err)
	}
	
	// Apply context filtering
	secrets = p.filterByContext(secrets)
	
	// Perform additional filtering to remove false positives
	filteredSecrets := p.filterFalsePositives(secrets)
	
	// Log each found secret
	for _, secret := range filteredSecrets {
		p.logger.SecretFound(secret.Type, secret.Value, secret.URL)
	}
	
	// Update stats
	p.mu.Lock()
	p.stats.SecretsFound += len(filteredSecrets)
	p.stats.ProcessingTime += time.Since(startTime)
	p.mu.Unlock()
	
	return filteredSecrets, nil
}

// filterFalsePositives applies additional filtering to remove false positives
func (p *Processor) filterFalsePositives(secrets []Secret) []Secret {
    filtered := make([]Secret, 0, len(secrets))
    
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
        "twilio_app_sid": {"Twilio", "twilio", "app", "application", "sid", "auth"},
        "Heroku API KEY": {"Heroku", "heroku", "HEROKU", "api", "key", "token", "auth", "secret"},
    }
    
    for _, secret := range secrets {
        // Check if it is base64 and likely not a secret
        if utils.IsBase64Encoded(secret.Value) && !utils.IsLikelySecretInBase64(secret.Value) {
            continue
        }
        
        // Check if the content appears to be a Base64 fragment
        if utils.IsLikelyBase64Fragment(secret.Value) {
            continue
        }
        
        // Check for false positive indicators in the context
        isValid := true
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
            filtered = append(filtered, secret)
        }
    }
    
    return filtered
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

