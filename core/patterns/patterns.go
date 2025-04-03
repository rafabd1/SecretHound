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
			KeywordExcludes: []string{"function", "example", "placeholder", "test", "demo", "origin-trial", "originTrial", "feature", "expiry", "recaptcha", "gstatic", "content=", "prepend", "minified", "compressed", "webpack", "bundle", "base64", "encoded", "data:", "source", "map", "+", "=", "==", "btoa", "atob", "encode", "padding", "charAt", "substring", "slice"},
		},
		"basic_auth": {
			Regex:       `(?i)(?:basic\s+)(?:[a-zA-Z0-9\+\/=]{10,100})`,
			Description: "HTTP Basic Authentication",
			Enabled:     true,
			MinLength:   15, // Adjusting minimum length to avoid "Basic usage" false positives
			KeywordExcludes: []string{
				"example", "sample", "usage", "caption", "documentation",
				"test", "@example", "description", "tutorial", "unicode",
				"Basic Multilingual", "BMP", "fromCharCode", 
				"createElement", "<h1", "<h2", "<h3", "<h4", "<h5", "<h6",
				"Basic authorization", "Basic authentication", "Basic configuration",
			},
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
			KeywordExcludes: []string{"QVO", "QUO", "YO", "accessToken:", ".accessToken", "oauth_token=", "variable", "config", "credential"},
		},

		// Generic secrets - Universal patterns
		"generic_password": {
			Regex:       `(?i)(?:password|passwd|pwd|secret)[\s]*[=:]+[\s]*["']([^'"]{8,30})["']`,
			Description: "Generic Password",
			Enabled:     true,
			MinLength:   8,
			MaxLength:   30,
			KeywordExcludes: []string{"match", "valid", "must", "should", "hint", "help", "message", "error", "Change password", "Reset password", "Forgot password", "pseudo", "selector", "createElement", "render", "component", "input[type", "USERNAME", "PASSWORD"},
		},
		
		// NOVOS PADRÕES ESPECÍFICOS (substituindo high_entropy_string)
		"auth_token": {
			Regex:       `['"]?([a-zA-Z0-9_\-\.]{32,64})['"]?\s*[,;]?\s*\/\/\s*[Aa]uth(?:entication)?\s+[Tt]oken`,
			Description: "Authentication Token",
			Enabled:     true,
			MinLength:   32,
			MaxLength:   64,
		},
		"api_key_assignment": {
			Regex:       `['"]?(?:api_?key|api_?secret|app_?key|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]`,
			Description: "API Key Assignment",
			Enabled:     true,
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test", "your", "xxx"},
		},
		"firebase_api_key": {
			Regex:       `AIzaSy[0-9A-Za-z_-]{33}`,
			Description: "Firebase API Key",
			Enabled:     true,
			MinLength:   39,
			KeywordExcludes: []string{"googleapis.com/webfonts", "fonts.googleapis", "webfonts?key="},
		},
		"github_personal_token": {
			Regex:       `gh[a-z]_[A-Za-z0-9_]{36,255}`,
			Description: "GitHub Personal Token",
			Enabled:     true,
			MinLength:   40,
		},
		"slack_token": {
			Regex:       `xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}`,
			Description: "Slack Token",
			Enabled:     true,
			MinLength:   40,
		},
		"slack_webhook": {
			Regex:       `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24,32}`,
			Description: "Slack Webhook URL",
			Enabled:     true,
			MinLength:   70,
		},
		"mailchimp_api_key": {
			Regex:       `[0-9a-zA-Z]{32}-us[0-9]{1,2}`,
			Description: "Mailchimp API Key",
			Enabled:     true,
			MinLength:   35,
		},
		"private_key_content": {
			Regex:       `-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY( BLOCK)?-----`,
			Description: "Private Key Content",
			Enabled:     true,
			MinLength:   30,
		},
		"square_access_token": {
			Regex:       `sq0atp-[0-9A-Za-z\-_]{22}`,
			Description: "Square Access Token",
			Enabled:     true,
			MinLength:   30,
		},
		"square_oauth_secret": {
			Regex:       `sq0csp-[0-9A-Za-z\-_]{43}`,
			Description: "Square OAuth Secret",
			Enabled:     true,
			MinLength:   50,
		},
		"sendgrid_api_key": {
			Regex:       `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,
			Description: "SendGrid API Key",
			Enabled:     true,
			MinLength:   69,
		},
		"encryption_key": {
			Regex:       `(?i)['"]?enc(?:ryption)?[_-]?key['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]`,
			Description: "Encryption Key",
			Enabled:     true,
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test"},
		},
		"signing_key": {
			Regex:       `(?i)['"]?sign(?:ing)?[_-]?(?:secret|key)['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]`,
			Description: "Signing Key/Secret",
			Enabled:     true,
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test"},
		},
		"heroku_api_key": {
			Regex:       `[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			Description: "Heroku API Key",
			Enabled:     true,
			MinLength:   30,
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
		"private_key_var": {
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

    // CSS variables and documentation
    "--", "css", "style", "class", "border-radius", "margin", "padding",
    "tooltip", "shadow", "background-color", "font-size", "wiki", "github",
    "example", "usage", "documentation", "tutorial", "sample", "@caption",
    "origin-trial", ".com/", "hover", "distance", "basic usage", "basic example",
    "freshchat_", "min_", "max_", "login", "uuid", "component", "module",
    "transition", "transform", "position", "display", "overflow", "align",
    "container", "wrapper", "element", "selector", "pattern", "template",
    
    // Novos padrões para JavaScript e UI
    "transition", "enable", "disable", "verify", "validate", "enroll", 
    "authenticate", "regenerate", "display", "postpone", "reminder",
    "constraint", "camelCase", "addEventListener", "querySelector",
    "dispatch", "onChange", "onClick", "onSubmit", "setState", "source", 
    "mapping", "sourceMappingURL", "INSUFFICIENT", "PASSWORD", "DISABLED",
    "fallback", "message", "prefix", "suffix", "handle", "callback",
    
    // Novos termos específicos para os falsos positivos identificados
    "Basic authorization", "Basic authentication", "Basic configuration", "Basic setup",
    "Basic usage", "Basic example", "Basic security", "Basic settings",
    "<h1", "<h2", "<h3", "<h4", "<h5", "<h6", "createElement",
    
    // Novos termos específicos para os falsos positivos identificados
    "Basic Multilingual", "BMP", "Unicode", "origin-trial", 
    "createElement", "render", "component", "Change password", 
    "access_token", "accessToken", ".accessToken", "oauth_token", 
    "webfonts", "googleapis.com", "type=\"password\"", "input[type=",
    "changingPassword", "resetPassword", "charCodeAt", "fromCharCode",

    // Excluir padrões específicos de código minificado com strings base64
    "data:image", "data:application", "sourceMappingURL", 
    "base64,", "/base64", "btoa(", "atob(", "encode(",
    "charAt(", "substring(", "slice(", "map(", "join(",
    "replace(", "split(", "charCode", "fromCharCode",
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
