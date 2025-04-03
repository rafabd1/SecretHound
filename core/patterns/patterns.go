package patterns

import (
	"regexp"
	"sync"
)

// PatternConfig representa a configuração para um padrão regex individual
type PatternConfig struct {
	Regex           string   // Expressão regular para encontrar o segredo
	Description     string   // Descrição do tipo de segredo
	Enabled         bool     // Se o padrão está habilitado
	MinLength       int      // Comprimento mínimo para valores válidos deste padrão
	MaxLength       int      // Comprimento máximo para valores válidos deste padrão
	KeywordMatches  []string // Palavras-chave que devem estar no contexto
	KeywordExcludes []string // Palavras-chave que não devem estar no contexto
	ExcludeRegexes  []string // Expressões regulares para excluir falsos positivos
}

// PatternDefinitions armazena a definição de todos os padrões de segredos
type PatternDefinitions struct {
	Patterns map[string]PatternConfig
}

// Global pattern definitions
var DefaultPatterns = &PatternDefinitions{
	Patterns: map[string]PatternConfig{
		// AWS - Critical cloud credentials
		"aws_access_key": {
			Regex:       `AKIA[0-9A-Z]{16}`,
			Description: "AWS Access Key ID",
			Enabled:     true,
			MinLength:   20,
			MaxLength:   20,
			KeywordMatches: []string{"aws", "amazon", "access", "key"},
		},
		"aws_secret_key": {
			Regex:       `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`,
			Description: "AWS Secret Access Key",
			Enabled:     true,
			MinLength:   40,
			MaxLength:   40,
			KeywordMatches: []string{"aws", "amazon", "secret"},
		},

		// Google - Widely used platform
		"google_api_key": {
			Regex:       `AIza[0-9A-Za-z\-_]{35}`,
			Description: "Google API Key",
			Enabled:     true,
			MinLength:   39,
			MaxLength:   39,
		},
		"google_oauth": {
			Regex:       `ya29\.[0-9A-Za-z\-_]+`,
			Description: "Google OAuth Access Token",
			Enabled:     true,
			MinLength:   30,
			KeywordMatches: []string{"oauth", "google", "token"},
		},
		"google_cloud_platform": {
			Regex:       `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
			Description: "Google Cloud Platform API Key",
			Enabled:     true,
			MinLength:   40,
		},

		// Payment processors - High risk exposure
		"stripe_secret_key": {
			Regex:       `sk_live_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Secret Key",
			Enabled:     true,
			MinLength:   30,
		},
		"stripe_publishable_key": {
			Regex:       `pk_live_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Publishable Key",
			Enabled:     true,
			MinLength:   30,
		},

		// Authentication tokens - Universal risk
		"jwt_token": {
			Regex:       `eyJ[a-zA-Z0-9_\-\.=]{10,500}`,
			Description: "JWT Token",
			Enabled:     true,
			MinLength:   30,
			KeywordExcludes: []string{"function", "example", "placeholder", "test", "demo"},
		},
		"basic_auth": {
			Regex:       `(?i)(?:basic\s*)(?:[a-zA-Z0-9\+\/=]{5,100})`,
			Description: "HTTP Basic Authentication",
			Enabled:     true,
			MinLength:   20,
		},
		"bearer_token": {
			Regex:       `(?i)bearer\s+[a-zA-Z0-9_\-\.=]{10,500}`,
			Description: "Bearer Token",
			Enabled:     true,
			MinLength:   20,
			KeywordExcludes: []string{"children", "autoComplete", "placeholder"},
		},
		"oauth_token": {
			Regex:       `(?i)(?:oauth|access)[._-]?token[.\s\'"]*[=:][.\s\'"]*[a-zA-Z0-9_\-\.=]{10,500}`,
			Description: "OAuth Token",
			Enabled:     true,
			MinLength:   20,
			KeywordExcludes: []string{"QVO", "QUO", "YO"},
		},

		// Generic secrets - Universal patterns
		"generic_password": {
			Regex:       `(?i)(?:password|passwd|pwd|secret)[\s]*[=:]+[\s]*["']([^'"]{8,30})["']`,
			Description: "Generic Password",
			Enabled:     true,
			MinLength:   8,
			MaxLength:   30,
			KeywordExcludes: []string{"match", "valid", "must", "should", "hint", "help", "message", "error"},
		},
		"high_entropy_string": {
			Regex:       `['"]?([a-zA-Z0-9+/=_\-]{32,64})['"]?`,
			Description: "High Entropy String",
			Enabled:     true,
			MinLength:   32,
			MaxLength:   64,
			KeywordExcludes: []string{"function", "return", "export", "import", "require"},
		},

		// Config/env file patterns - Common local file patterns
		"config_api_key": {
			Regex:       `['"]?(?:api|app)(?:_|-|\.)?(?:key|token|secret)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
			Description: "Configuration API Key",
			Enabled:     true,
			MinLength:   8,
		},
		"config_secret": {
			Regex:       `['"]?(?:secret|private|auth)(?:_|-|\.)?(?:key|token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
			Description: "Configuration Secret",
			Enabled:     true,
			MinLength:   8,
		},
		"mongodb_uri": {
			Regex:       `mongodb(?:\+srv)?://[^:]+:([^@]+)@`,
			Description: "MongoDB Connection URI",
			Enabled:     true,
			MinLength:   8,
		},
		"private_key": {
			Regex:       `['"]?(?:private_?key|secret_?key)['"]?\s*[:=]\s*['"]([^'"]{20,})['"]`,
			Description: "Private Key Variable",
			Enabled:     true,
			MinLength:   20,
		},
		
		// GitHub tokens - High risk for code repository access
		"github_token": {
			Regex:       `ghp_[0-9a-zA-Z]{36}`,
			Description: "GitHub Personal Access Token",
			Enabled:     true,
			MinLength:   40,
		},
		
		// Azure - Major cloud provider
		"azure_connection_string": {
			Regex:       `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=`,
			Description: "Azure Storage Connection String",
			Enabled:     true,
			MinLength:   70,
		},
	},
}

// Global list of excluded strings that are likely false positives
var GlobalExclusions = []string{
	// Common code patterns
	"function", "return", "import", "export", "require",
	"console.log", "window.", "document.", "getElementById",
	"querySelector", "addEventListener", "module.exports",
	
	// Common file paths
	"node_modules", "/dist/", "/build/", "/src/", "/public/",
	
	// Media types
	"application/json", "text/html", "text/plain",
	
	// HTML DOM elements
	"div", "span", "input", "button", "form",
	
	// Development-related
	"localhost", "127.0.0.1", "0.0.0.0", "test", "example",
	"development", "staging", "production",
}

// CompiledPattern represents a pattern with its compiled regex
type CompiledPattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Config      PatternConfig
}

// PatternManager manages regex patterns for secret detection
type PatternManager struct {
	compiledPatterns     map[string]*CompiledPattern
	exclusionPatterns    []*regexp.Regexp
	specificExclusions   map[string][]*regexp.Regexp
	localModeEnabled     bool
	mu                   sync.RWMutex
}

// NewPatternManager creates a new pattern manager instance
func NewPatternManager() *PatternManager {
	pm := &PatternManager{
		compiledPatterns:   make(map[string]*CompiledPattern),
		exclusionPatterns:  make([]*regexp.Regexp, 0),
		specificExclusions: make(map[string][]*regexp.Regexp),
	}
	
	// Load the default patterns
	pm.LoadDefaultPatterns()
	
	return pm
}

// LoadDefaultPatterns loads the default pattern set
func (pm *PatternManager) LoadDefaultPatterns() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Reset existing patterns
	pm.compiledPatterns = make(map[string]*CompiledPattern)
	
	// Compile each pattern
	for name, config := range DefaultPatterns.Patterns {
		if !config.Enabled {
			continue
		}
		
		re, err := regexp.Compile(config.Regex)
		if err != nil {
			return err
		}
		
		pm.compiledPatterns[name] = &CompiledPattern{
			Name:        name,
			Description: config.Description,
			Regex:       re,
			Config:      config,
		}
	}
	
	// Compile global exclusions
	for _, exclusion := range GlobalExclusions {
		re, err := regexp.Compile(regexp.QuoteMeta(exclusion))
		if err != nil {
			continue
		}
		pm.exclusionPatterns = append(pm.exclusionPatterns, re)
	}
	
	return nil
}

// SetLocalMode enables or disables local file mode
func (pm *PatternManager) SetLocalMode(enabled bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.localModeEnabled = enabled
}

// IsLocalModeEnabled returns whether local mode is enabled
func (pm *PatternManager) IsLocalModeEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.localModeEnabled
}

// GetPatternCount returns the number of compiled patterns
func (pm *PatternManager) GetPatternCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.compiledPatterns)
}

// GetCompiledPatterns returns all compiled patterns
func (pm *PatternManager) GetCompiledPatterns() map[string]*CompiledPattern {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent modification
	patterns := make(map[string]*CompiledPattern, len(pm.compiledPatterns))
	for k, v := range pm.compiledPatterns {
		patterns[k] = v
	}
	
	return patterns
}

// AddPattern adds a new pattern
func (pm *PatternManager) AddPattern(name, regex, description string) error {
	re, err := regexp.Compile(regex)
	if err != nil {
		return err
	}
	
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.compiledPatterns[name] = &CompiledPattern{
		Name:        name,
		Description: description,
		Regex:       re,
		Config: PatternConfig{
			Regex:       regex,
			Description: description,
			Enabled:     true,
			MinLength:   8,  // Default minimum length
			MaxLength:   500, // Default maximum length
		},
	}
	
	return nil
}

// Reset resets the pattern manager to its initial state
func (pm *PatternManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.compiledPatterns = make(map[string]*CompiledPattern)
	pm.exclusionPatterns = make([]*regexp.Regexp, 0)
	pm.specificExclusions = make(map[string][]*regexp.Regexp)
	pm.localModeEnabled = false
}
