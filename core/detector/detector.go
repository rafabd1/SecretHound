package detector

import (
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
	if len(patterns) == 0 {
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

// validateSecret validates if a potential secret is valid
func (d *Detector) validateSecret(
	patternName, value, context string, 
	isExampleContent bool,
) (bool, float64) {
	// First, get the pattern config
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
	
	// In local file mode with example content, be less strict if allowed
	if d.config.LocalFileMode && isExampleContent && d.config.AllowTestExamples {
		// Just do basic validation for example/test content
		return !containsCommonFalsePositive(value), 0.7
	}
	
	// Check if matches exclusion keywords
	for _, keyword := range config.KeywordExcludes {
		if strings.Contains(value, keyword) || strings.Contains(context, keyword) {
			return false, 0
		}
	}
	
	// Check code patterns that indicate false positives
	if hasCodePattern(value) {
		return false, 0
	}
	
	// Calculate confidence based on pattern-specific factors
	confidence := calculateConfidence(patternName, value, context)
	
	// In local file mode, adjust confidence
	if d.config.LocalFileMode {
		// Slightly boost confidence for local files
		confidence += 0.1
	}
	
	return true, confidence
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
