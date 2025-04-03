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
		
		
		// Adição de novos padrões para bancos de dados
		"postgresql_connection_string": {
			Regex:       `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+\/\w+`,
			Description: "PostgreSQL Connection String",
			Enabled:     true,
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"mongodb_srv_connection": {
			Regex:       `mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+\/[^?]+`,
			Description: "MongoDB SRV Connection String",
			Enabled:     true,
			MinLength:   40,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"mysql_connection_string": {
			Regex:       `mysql:\/\/[^:]+:[^@]+@[^\/]+\/\w+`,
			Description: "MySQL Connection String",
			Enabled:     true,
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"redis_url": {
			Regex:       `redis(?::\\/\\/)[^:]+:[^@]+@[^\/]+(?::\d+)?`,
			Description: "Redis Connection URL",
			Enabled:     true,
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"msql_connection_string": {
			Regex:       `Server=.+;Database=.+;User (?:ID|Id)=.+;Password=.+;`,
			Description: "Microsoft SQL Server Connection String",
			Enabled:     true,
			MinLength:   40,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		
		// Serviços Cloud e APIs
		"mailgun_api_key": {
			Regex:       `key-[0-9a-zA-Z]{32}`,
			Description: "Mailgun API Key",
			Enabled:     true,
			MinLength:   36,
		},
		"digitalocean_access_token": {
			Regex:       `dop_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean Personal Access Token",
			Enabled:     true,
			MinLength:   69,
		},
		"digitalocean_oauth_token": {
			Regex:       `doo_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean OAuth Token",
			Enabled:     true,
			MinLength:   69,
		},
		"digitalocean_refresh_token": {
			Regex:       `dor_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean Refresh Token",
			Enabled:     true,
			MinLength:   69,
		},
		"shopify_access_token": {
			Regex:       `shpat_[a-fA-F0-9]{32}`,
			Description: "Shopify Access Token",
			Enabled:     true,
			MinLength:   38,
		},
		"shopify_custom_app_token": {
			Regex:       `shpca_[a-fA-F0-9]{32}`,
			Description: "Shopify Custom App Access Token",
			Enabled:     true,
			MinLength:   38,
		},
		"shopify_private_app_token": {
			Regex:       `shppa_[a-fA-F0-9]{32}`,
			Description: "Shopify Private App Access Token",
			Enabled:     true,
			MinLength:   38,
		},
		"shopify_shared_secret": {
			Regex:       `shpss_[a-fA-F0-9]{32}`,
			Description: "Shopify Shared Secret",
			Enabled:     true,
			MinLength:   38,
		},
		"npm_access_token": {
			Regex:       `npm_[A-Za-z0-9]{36}`,
			Description: "NPM Access Token",
			Enabled:     true,
			MinLength:   40,
		},
		"docker_hub_token": {
			Regex:       `dckr_pat_[A-Za-z0-9_-]{56}`,
			Description: "Docker Hub Personal Access Token",
			Enabled:     true,
			MinLength:   64,
		},
		
		// Serviços de Pagamento
		"paypal_client_id": {
			Regex:       `(?i)(?:paypal|braintree).{0,20}['\"][A-Za-z0-9_-]{20,64}['\"]`,
			Description: "PayPal Client ID",
			Enabled:     true,
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample"},
		},
		"paypal_client_secret": {
			Regex:       `(?i)(?:paypal|braintree).{0,20}['\"][A-Za-z0-9_-]{20,64}['\"]`,
			Description: "PayPal Client Secret",
			Enabled:     true,
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample"},
		},
		"braintree_token": {
			Regex:       `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			Description: "Braintree Access Token",
			Enabled:     true,
			MinLength:   67,
		},
		"stripe_test_secret_key": {
			Regex:       `sk_test_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Test Secret Key",
			Enabled:     true,
			MinLength:   30,
		},
		"stripe_test_publishable_key": {
			Regex:       `pk_test_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Test Publishable Key",
			Enabled:     true,
			MinLength:   30,
		},
		
		// Serviços de Email
		"mailchimp_api_key": {
			Regex:       `[0-9a-f]{32}-us[0-9]{1,2}`,
			Description: "Mailchimp API Key",
			Enabled:     true,
			MinLength:   36,
		},
		"sendgrid_api_key": {
			Regex:       `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,
			Description: "SendGrid API Key",
			Enabled:     true,
			MinLength:   69,
		},
		
		// Microsoft Azure
		"azure_connection_string": {
			Regex:       `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=`,
			Description: "Azure Storage Connection String",
			Enabled:     true,
			MinLength:   70,
		},
		"azure_sql_connection": {
			Regex:       `Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;`,
			Description: "Azure SQL Connection String",
			Enabled:     true,
			MinLength:   50,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"azure_service_bus": {
			Regex:       `Endpoint=sb:\/\/[^.]+\.servicebus\.windows\.net\/;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+`,
			Description: "Azure Service Bus Connection String",
			Enabled:     true,
			MinLength:   60,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"azure_cosmosdb": {
			Regex:       `AccountEndpoint=https:\/\/[^.]+\.documents\.azure\.com:443\/;AccountKey=[^;]+;`,
			Description: "Azure CosmosDB Connection String",
			Enabled:     true,
			MinLength:   70,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		
		// JWT e OAuth - Melhorias nos padrões existentes
		"jwt_improved": {
			Regex:       `eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`,
			Description: "JWT Token (Improved Pattern)",
			Enabled:     true,
			MinLength:   30,
			KeywordExcludes: []string{"function", "example", "placeholder", "test", "demo", "origin-trial"},
		},
		"oauth2_access_token": {
			Regex:       `ya29\.[0-9A-Za-z\-_]+`,
			Description: "OAuth 2.0 Access Token",
			Enabled:     true,
			MinLength:   30,
		},
		
		// Serviços de CI/CD
		"gitlab_runner_token": {
			Regex:       `glrt-[0-9a-zA-Z_\-]{20,}`,
			Description: "GitLab Runner Registration Token",
			Enabled:     true,
			MinLength:   25,
		},
		"gitlab_personal_token": {
			Regex:       `glpat-[0-9a-zA-Z_\-]{20,}`,
			Description: "GitLab Personal Access Token",
			Enabled:     true,
			MinLength:   25,
		},
		"jenkins_api_token": {
			Regex:       `(?i)(?:jenkins|hudson).{0,5}(?:api)?.{0,5}(?:token).{0,5}['\"]([0-9a-zA-Z]{30,})['\"]`,
			Description: "Jenkins API Token",
			Enabled:     true,
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample"},
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
    "webfonts", "googleapis.com", "type=\"password\"", "input[type=", 
	"charCodeAt", "fromCharCode",

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
	
	// MODIFICAÇÃO: Contador para depuração
	enabledPatterns := 0
	
	// Compile each pattern
	for name, config := range DefaultPatterns.Patterns {
		if !config.Enabled {
			continue
		}
		
		enabledPatterns++
		
		re, err := regexp.Compile(config.Regex)
		if err != nil {
			continue
		}
		
		pm.compiledPatterns[name] = &CompiledPattern{
			Name:        name,
			Description: config.Description,
			Regex:       re,
			Config:      config,
		}
	}
	
	// MODIFICAÇÃO: Reduzir exclusões globais para diminuir falsos negativos
	// Compile global exclusions - apenas as mais críticas
	criticalExclusions := []string{
		"example", "sample", "test", "demo",
		"function(", "return",
	}
	
	for _, exclusion := range criticalExclusions {
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
	if (err != nil) {
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
