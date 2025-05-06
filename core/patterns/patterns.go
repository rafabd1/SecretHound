package patterns

import (
	"regexp"
	"sync"
)

type PatternConfig struct {
	Regex           string
	Description     string
	Enabled         bool
	Category        string
	MinLength       int
	MaxLength       int
	KeywordMatches  []string
	KeywordExcludes []string
	ExcludeRegexes  []string
}

type PatternDefinitions struct {
	Patterns map[string]PatternConfig
}

var DefaultPatterns = &PatternDefinitions{
	Patterns: map[string]PatternConfig{
		// AWS - Critical cloud credentials
		"aws_access_key": {
			Regex:       `AKIA[0-9A-Z]{16}`,
			Description: "AWS Access Key ID",
			Enabled:     true,
			Category:    "aws",
			MinLength:   20,
			MaxLength:   20,
			KeywordMatches: []string{"aws", "amazon", "access", "key"},
		},
		"aws_secret_key": {
			Regex:       `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`,
			Description: "AWS Secret Access Key",
			Enabled:     true,
			Category:    "aws",
			MinLength:   40,
			MaxLength:   40,
			KeywordMatches: []string{"aws", "amazon", "secret"},
		},

		// Google - Widely used platform
		"google_api_key": {
			Regex:       `AIza[0-9A-Za-z\-_]{35}`,
			Description: "Google API Key",
			Enabled:     true,
			Category:    "gcp",
			MinLength:   39,
			MaxLength:   39,
		},
		"google_cloud_platform": {
			Regex:       `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
			Description: "Google Cloud Platform API Key",
			Enabled:     true,
			Category:    "gcp",
			MinLength:   40,
		},

		// Payment processors - High risk exposure
		"stripe_secret_key": {
			Regex:       `sk_live_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Secret Key",
			Enabled:     true,
			Category:    "payment",
			MinLength:   30,
		},
		"stripe_publishable_key": {
			Regex:       `pk_live_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Publishable Key",
			Enabled:     true,
			Category:    "payment",
			MinLength:   30,
		},

		// Authentication tokens - Universal risk
		"jwt_token": {
			Regex:       `eyJ[a-zA-Z0-9_\-]+\\.[a-zA-Z0-9_\-]+\\.[a-zA-Z0-9_\-]+`,
			Description: "JWT Token",
			Enabled:     true,
			Category:    "auth",
			MinLength:   30,
			KeywordExcludes: []string{"function", "example", "placeholder", "test", "demo", "origin-trial"},
		},
		"basic_auth": {
			Regex:       `(?i)(?:basic\\s+)(?:[a-zA-Z0-9\\+\\/=]{20,100}=*)`,
			Description: "HTTP Basic Authentication",
			Enabled:     false,
			Category:    "auth",
			MinLength:   25,
			KeywordExcludes: []string{
				"example", "sample", "usage", "caption", "documentation",
				"test", "@example", "description", "tutorial", "unicode",
				"Basic Multilingual", "BMP", "fromCharCode",
				"createElement", "<h1", "<h2", "<h3", "<h4", "<h5", "<h6",
				"Basic authorization", "Basic authentication", "Basic configuration",
			},
		},
		"bearer_token": {
			Regex:       `(?i)bearer\\s+[a-zA-Z0-9_\\-\\.=]{10,500}`,
			Description: "Bearer Token",
			Enabled:     true,
			Category:    "auth",
			MinLength:   20,
			KeywordExcludes: []string{"QVO", "QUO", "YO", "accessToken:", ".accessToken", "oauth_token=", "variable", "config", "credential", "INVALID_ACCESS_TOKEN", "MISSING_ACCESS_TOKEN"},
		},
		"oauth_token": {
			Regex:       `(?i)(?:oauth|access)[._-]?token\\s*[:=]\\s*['"]([a-zA-Z0-9_\\-\\.=]{32,500})['"]`,
			Description: "OAuth Token",
			Enabled:     true,
			Category:    "auth",
			MinLength:   32,
			KeywordExcludes: []string{"QVO", "QUO", "YO", "accessToken:", ".accessToken", "oauth_token=", "variable", "config", "credential", "INVALID_ACCESS_TOKEN", "MISSING_ACCESS_TOKEN", "error", "payment_widget_", "_error_", "setAuthTokens", "webhooks_"},
		},

		// Generic secrets - Universal patterns
		"generic_password": {
			Regex:       `(?i)(?:password|passwd|pwd|secret)[\\s]*[=:]+[\\s]*["']([^'"]{8,30})["']`,
			Description: "Generic Password",
			Enabled:     false,
			Category:    "generic",
			MinLength:   8,
			MaxLength:   30,
			KeywordExcludes: []string{"match", "valid", "must", "should", "hint", "help", "message", "error", "Change password", "Reset password", "Forgot password", "pseudo", "selector", "createElement", "render", "component", "input[type", "USERNAME", "PASSWORD", "[REDACTED]", "switch_to_"},
		},

		// Specific patterns
		"auth_token": {
			Regex:       `['"]?([a-zA-Z0-9_\-\.]{32,64})['"]?\s*[,;]?\s*\/\/\s*[Aa]uth(?:entication)?\s+[Tt]oken`,
			Description: "Authentication Token (Comment Based)",
			Enabled:     true,
			Category:    "auth",
			MinLength:   32,
			MaxLength:   64,
		},
		"api_key_assignment": {
			Regex:       `['"]?(?:api_?key|api_?secret|app_?key|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]`,
			Description: "API Key Assignment",
			Enabled:     true,
			Category:    "generic",
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test", "your", "xxx"},
		},
		"github_personal_token": {
			Regex:       `gh[a-z]_[A-Za-z0-9_]{36,255}`,
			Description: "GitHub Personal Token",
			Enabled:     true,
			Category:    "code",
			MinLength:   40,
		},
		"slack_token": {
			Regex:       `xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}`,
			Description: "Slack Token",
			Enabled:     true,
			Category:    "code",
			MinLength:   40,
		},
		"slack_webhook": {
			Regex:       `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24,32}`,
			Description: "Slack Webhook URL",
			Enabled:     true,
			Category:    "code",
			MinLength:   70,
		},
		"private_key_content": {
			Regex:       `-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY( BLOCK)?-----`,
			Description: "Private Key Content (BEGIN Block)",
			Enabled:     true,
			Category:    "crypto",
			MinLength:   30,
		},
		"square_access_token": {
			Regex:       `sq0atp-[0-9A-Za-z\-_]{22}`,
			Description: "Square Access Token",
			Enabled:     true,
			Category:    "payment",
			MinLength:   30,
		},
		"square_oauth_secret": {
			Regex:       `sq0csp-[0-9A-Za-z\-_]{43}`,
			Description: "Square OAuth Secret",
			Enabled:     true,
			Category:    "payment",
			MinLength:   50,
		},
		"encryption_key": {
			Regex:       `(?i)['"]?enc(?:ryption)?[_-]?key['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]`,
			Description: "Encryption Key",
			Enabled:     true,
			Category:    "crypto",
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test"},
		},
		"signing_key": {
			Regex:       `(?i)['"]?sign(?:ing)?[_-]?(?:secret|key)['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]`,
			Description: "Signing Key/Secret",
			Enabled:     true,
			Category:    "crypto",
			MinLength:   16,
			KeywordExcludes: []string{"example", "sample", "placeholder", "test"},
		},
		"heroku_api_key": {
			Regex:       `[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			Description: "Heroku API Key",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   30,
		},

		// Config/env file patterns - Common local file patterns
		"config_api_key": {
			Regex:       `['"]?(?:api|app)(?:_|-|\.)?(?:key|token|secret)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
			Description: "Configuration API Key",
			Enabled:     true,
			Category:    "config",
			MinLength:   8,
		},
		"config_secret": {
			Regex:       `['"]?(?:secret|private|auth)(?:_|-|\.)?(?:key|token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
			Description: "Configuration Secret",
			Enabled:     true,
			Category:    "config",
			MinLength:   8,
		},
		"mongodb_uri": {
			Regex:       `mongodb(?:\+srv)?:\/\/[^:]+:([^@]+)@`,
			Description: "MongoDB Connection URI",
			Enabled:     true,
			Category:    "db",
			MinLength:   8,
		},
		"private_key_var": {
			Regex:       `['"]?(?:private_?key|secret_?key)['"]?\s*[:=]\s*['"]([^'"]{20,})['"]`,
			Description: "Private Key Variable",
			Enabled:     true,
			Category:    "crypto",
			MinLength:   20,
		},

		// GitHub tokens - High risk for code repository access
		"github_token": {
			Regex:       `ghp_[0-9a-zA-Z]{36}`,
			Description: "GitHub Personal Access Token (New Format)",
			Enabled:     true,
			Category:    "code",
			MinLength:   40,
		},

		// Database connection strings
		"postgresql_connection_string": {
			Regex:       `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+\/\w+`,
			Description: "PostgreSQL Connection String",
			Enabled:     true,
			Category:    "db",
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"mongodb_srv_connection": {
			Regex:       `mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+\/[^?]+`,
			Description: "MongoDB SRV Connection String",
			Enabled:     true,
			Category:    "db",
			MinLength:   40,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"mysql_connection_string": {
			Regex:       `mysql:\/\/[^:]+:[^@]+@[^\/]+\/\w+`,
			Description: "MySQL Connection String",
			Enabled:     true,
			Category:    "db",
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"redis_url": {
			Regex:       `redis(?::\\/\\/)[^:]+:[^@]+@[^\/]+(?::\d+)?`,
			Description: "Redis Connection URL",
			Enabled:     true,
			Category:    "db",
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"msql_connection_string": {
			Regex:       `Server=.+;Database=.+;User (?:ID|Id)=.+;Password=.+;`,
			Description: "Microsoft SQL Server Connection String",
			Enabled:     true,
			Category:    "db",
			MinLength:   40,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},

		// Cloud services and APIs
		"mailgun_api_key": {
			Regex:       `key-[0-9a-zA-Z]{32}`,
			Description: "Mailgun API Key",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   36,
			KeywordExcludes: []string{".js", ".css", ".map", "/assets/", "ace/mode"},
		},
		"digitalocean_access_token": {
			Regex:       `dop_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean Personal Access Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   69,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample"},
		},
		"digitalocean_oauth_token": {
			Regex:       `doo_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean OAuth Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   69,
		},
		"digitalocean_refresh_token": {
			Regex:       `dor_v1_[a-f0-9]{64}`,
			Description: "DigitalOcean Refresh Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   69,
		},
		"shopify_access_token": {
			Regex:       `shpat_[a-fA-F0-9]{32}`,
			Description: "Shopify Access Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   38,
		},
		"shopify_custom_app_token": {
			Regex:       `shpca_[a-fA-F0-9]{32}`,
			Description: "Shopify Custom App Access Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   38,
		},
		"shopify_private_app_token": {
			Regex:       `shppa_[a-fA-F0-9]{32}`,
			Description: "Shopify Private App Access Token",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   38,
		},
		"shopify_shared_secret": {
			Regex:       `shpss_[a-fA-F0-9]{32}`,
			Description: "Shopify Shared Secret",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   38,
		},
		"npm_access_token": {
			Regex:       `npm_[A-Za-z0-9]{36}`,
			Description: "NPM Access Token",
			Enabled:     true,
			Category:    "code",
			MinLength:   40,
		},
		"docker_hub_token": {
			Regex:       `dckr_pat_[A-Za-z0-9_-]{56}`,
			Description: "Docker Hub Personal Access Token",
			Enabled:     true,
			Category:    "code",
			MinLength:   64,
		},

		// Payment services
		"paypal_client_id": {
			Regex:       `(?i)(?:paypal|braintree).{0,20}(?:[:=]\s*)['"]([A-Za-z0-9_-]{20,64})['"]`,
			Description: "PayPal/Braintree Client ID",
			Enabled:     true,
			Category:    "payment",
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample", "kill_"},
		},
		"paypal_client_secret": {
			Regex:       `(?i)(?:paypal|braintree).{0,20}(?:[:=]\s*)['"]([A-Za-z0-9_-]{20,64})['"]`,
			Description: "PayPal/Braintree Client Secret",
			Enabled:     true,
			Category:    "payment",
			MinLength:   20,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample", "kill_"},
		},
		"braintree_token": {
			Regex:       `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			Description: "Braintree Access Token",
			Enabled:     true,
			Category:    "payment",
			MinLength:   67,
		},
		"stripe_test_secret_key": {
			Regex:       `sk_test_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Test Secret Key",
			Enabled:     true,
			Category:    "payment",
			MinLength:   30,
		},
		"stripe_test_publishable_key": {
			Regex:       `pk_test_[0-9a-zA-Z]{24,34}`,
			Description: "Stripe Test Publishable Key",
			Enabled:     true,
			Category:    "payment",
			MinLength:   30,
		},

		// Email services
		"mailchimp_api_key": {
			Regex:       `[0-9a-f]{32}-us[0-9]{1,2}`,
			Description: "Mailchimp API Key",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   36,
		},
		"sendgrid_api_key": {
			Regex:       `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,
			Description: "SendGrid API Key",
			Enabled:     true,
			Category:    "cloud",
			MinLength:   69,
		},

		// Microsoft Azure
		"azure_connection_string": {
			Regex:       `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=`,
			Description: "Azure Storage Connection String",
			Enabled:     true,
			Category:    "azure",
			MinLength:   70,
		},
		"azure_sql_connection": {
			Regex:       `Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;`,
			Description: "Azure SQL Connection String",
			Enabled:     true,
			Category:    "azure",
			MinLength:   50,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"azure_service_bus": {
			Regex:       `Endpoint=sb:\/\/[^.]+\.servicebus\.windows\.net\/;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+`,
			Description: "Azure Service Bus Connection String",
			Enabled:     true,
			Category:    "azure",
			MinLength:   60,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},
		"azure_cosmosdb": {
			Regex:       `AccountEndpoint=https:\/\/[^.]+\.documents\.azure\.com:443\/;AccountKey=[^;]+;`,
			Description: "Azure CosmosDB Connection String",
			Enabled:     true,
			Category:    "azure",
			MinLength:   70,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "localhost", "sample"},
		},

		// JWT and OAuth improved patterns
		"oauth2_access_token": {
			Regex:       `ya29\.[0-9A-Za-z\-_]+`,
			Description: "OAuth 2.0 Access Token (Google/Firebase)",
			Enabled:     true,
			Category:    "auth",
			MinLength:   30,
		},

		// CI/CD services
		"gitlab_runner_token": {
			Regex:       `glrt-[0-9a-zA-Z_\-]{20,}`,
			Description: "GitLab Runner Registration Token",
			Enabled:     true,
			Category:    "ci",
			MinLength:   25,
		},
		"gitlab_personal_token": {
			Regex:       `glpat-[0-9a-zA-Z_\-]{20,}`,
			Description: "GitLab Personal Access Token",
			Enabled:     true,
			Category:    "ci",
			MinLength:   25,
		},
		"jenkins_api_token": {
			Regex:       `(?i)(?:jenkins|hudson).{0,5}(?:api)?.{0,5}(?:token).{0,5}['"]([0-9a-zA-Z]{30,})['"]`,
			Description: "Jenkins API Token",
			Enabled:     true,
			Category:    "ci",
			MinLength:   30,
			KeywordExcludes: []string{"example", "placeholder", "user", "password", "sample"},
		},

		// --- PII (Personally Identifiable Information) Patterns ---
		"email_address": {
			Regex:       `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Description: "Email Address",
			Enabled:     true,
			Category:    "pii",
			MinLength:   6,
			KeywordMatches: []string{"email", "mail", "address"},
			KeywordExcludes: []string{"example", "test", "demo", "noreply", "no-reply", "@example.com", "@test.com"},
		},
		"phone_number": {
			Regex:       `(?i)(?:phone|mobile|tel(?:ephone)?)[^\n\r]{0,20}(?:[:= ]*)(\+?\d{1,3}[-.\s]?)?(\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b`,
			Description: "Phone Number",
			Enabled:     true,
			Category:    "pii",
			MinLength:   10,
			KeywordExcludes: []string{"version", "id", "example", "test", "port"},
		},
		"ipv4_address": {
			Regex:       `\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			Description: "IPv4 Address (Public)",
			Enabled:     true,
			Category:    "pii",
			MinLength:   7,
			MaxLength:   15,
			KeywordMatches: []string{"ip", "address", "host"},
			KeywordExcludes: []string{"0.0.0.0", "127.0.0.1", "localhost"},
		},
		"ipv6_address": {
			Regex:       `\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b`,
			Description: "IPv6 Address",
			Enabled:     true,
			Category:    "pii",
			MinLength:   3,
			KeywordMatches: []string{"ip", "address", "host"},
			KeywordExcludes: []string{"::1", "localhost", "//", "/*", "* "},
		},
		"mac_address": {
			Regex:       `\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b`,
			Description: "MAC Address",
			Enabled:     true,
			Category:    "pii",
			MinLength:   17,
			MaxLength:   17,
			KeywordMatches: []string{"mac", "address", "ethernet"},
		},
		"us_zip_code": {
			Regex:       `(?i)(?:zip|postal|post_?code|address)\\s*[:=]\\s*(\\d{5}(?:-\\d{4})?)\\b`,
			Description: "US ZIP Code (Keyword Dependent)",
			Enabled:     true,
			Category:    "pii",
			MinLength:   5,
			MaxLength:   10,
			KeywordMatches: []string{"zip", "postal", "postcode"},
			KeywordExcludes: []string{"version", "build", "port"},
		},
		"serial_number": {
			Regex:       `(?i)(?:serial|s\\/n)\\s*[:=]\\s*([A-Za-z0-9\\-]{8,40})\\b`,
			Description: "Serial Number (Keyword Dependent)",
			Enabled:     true,
			Category:    "pii",
			MinLength:   8,
			MaxLength:   40,
			KeywordExcludes: []string{"example", "test", "uuid", "guid", "session", "request"},
		},
		// --- End PII Patterns ---

		// --- Web3 / Blockchain Patterns ---
		"ethereum_address": {
			Regex:       `\b0x[a-fA-F0-9]{40}\b`,
			Description: "Ethereum Address",
			Enabled:     true,
			Category:    "web3",
			MinLength:   42,
			MaxLength:   42,
			KeywordMatches: []string{"address", "ethereum", "wallet", "contract", "account"},
			KeywordExcludes: []string{"example", "test", "null", "0x0", "0x000", "zero"},
		},
		"web3_private_key": {
			Regex:       `(?i)(?:private[._-]?key|secret|wallet|mnemonic|seed|private_key_hex)\s*[:=]\s*['"]?(0x?[a-fA-F0-9]{64})['"]?`,
			Description: "Web3 Private Key (Keyword Dependent)",
			Enabled:     true,
			Category:    "web3",
			MinLength:   64,
			KeywordExcludes: []string{"example", "test", "placeholder", "sample"},
		},
		"mnemonic_phrase": {
			Regex:       `(?i)(?:mnemonic|seed|phrase|backup|recovery)(?:[^a-z\n\r]*[\s:=]+){1,5}(\b(?:[a-z]+\s+){11}[a-z]+\b|\b(?:[a-z]+\s+){23}[a-z]+\b)`,
			Description: "Mnemonic/Seed Phrase (Keyword Dependent)",
			Enabled:     true,
			Category:    "web3",
			MinLength:   40,
			KeywordExcludes: []string{"example", "test", "placeholder", "sample", "instructions", "tutorial", "words", "wordlist"},
		},
		"web3_provider_key": {
			Regex:       `(?i)(?:infura|alchemy|quicknode|moralis|ankr).{0,20}(?:api[._-]?key|project[._-]?id|app[._-]?id|secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,64})['"]?`,
			Description: "Web3 Provider API Key/ID (Infura, Alchemy, etc.)",
			Enabled:     true,
			Category:    "web3",
			MinLength:   32,
			KeywordExcludes: []string{"example", "test", "placeholder", "sample", "YOUR_API_KEY", "PROJECT_ID"},
		},
		// --- End Web3 Patterns ---
	},
}

// List of strings likely to be false positives
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
	
	// JavaScript and UI patterns
	"transition", "enable", "disable", "verify", "validate", "enroll", 
	"authenticate", "regenerate", "display", "postpone", "reminder",
	"constraint", "camelCase", "addEventListener", "querySelector",
	"dispatch", "onChange", "onClick", "onSubmit", "setState", "source", 
	"mapping", "sourceMappingURL", "INSUFFICIENT", "PASSWORD", "DISABLED",
	"fallback", "message", "prefix", "suffix", "handle", "callback",
	
	// Specific terms for false positives
	"Basic authorization", "Basic authentication", "Basic configuration", "Basic setup",
	"Basic usage", "Basic example", "Basic security", "Basic settings",
	"<h1", "<h2", "<h3", "<h4", "<h5", "<h6", "createElement",
	
	// More specific false positive terms
	"Basic Multilingual", "BMP", "Unicode", "origin-trial", 
	"createElement", "render", "component", "Change password", 
	"webfonts", "googleapis.com", "type=\"password\"", "input[type=", 
	"charCodeAt", "fromCharCode",

	// Code minified with base64 strings
	"data:image", "data:application", "sourceMappingURL", 
	"base64,", "/base64", "btoa(", "atob(", "encode(",
	"charAt(", "substring(", "slice(", "map(", "join(",
	"replace(", "split(", "charCode", "fromCharCode",
}

type CompiledPattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Config      PatternConfig
}

type PatternManager struct {
	compiledPatterns     map[string]*CompiledPattern
	exclusionPatterns    []*regexp.Regexp
	specificExclusions   map[string][]*regexp.Regexp
	localModeEnabled     bool
	mu                   sync.RWMutex
}

/* 
   Creates a new pattern manager instance with default configuration
*/
func NewPatternManager() *PatternManager {
	pm := &PatternManager{
		compiledPatterns:   make(map[string]*CompiledPattern),
		exclusionPatterns:  make([]*regexp.Regexp, 0),
		specificExclusions: make(map[string][]*regexp.Regexp),
	}

	// Load default patterns upon initialization using the new method
	// This ensures the manager is ready immediately, respecting potential future config
	// that might influence loading later (though flags are handled separately in cmd).
	// We call with nil filters to load all enabled patterns by default.
	_ = pm.LoadPatterns(nil, nil) // Error handling could be added if needed here

	return pm
}

/* 
   Loads and compiles patterns based on category filters.
   Accepts include/exclude category lists. Only one should be non-empty.
*/
func (pm *PatternManager) LoadPatterns(includeCategories, excludeCategories []string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.compiledPatterns = make(map[string]*CompiledPattern)

	includeMap := make(map[string]bool)
	for _, cat := range includeCategories {
		includeMap[cat] = true
	}

	excludeMap := make(map[string]bool)
	for _, cat := range excludeCategories {
		excludeMap[cat] = true
	}

	useInclude := len(includeCategories) > 0
	useExclude := len(excludeCategories) > 0

	enabledPatterns := 0

	for name, config := range DefaultPatterns.Patterns {
		if !config.Enabled {
			continue
		}

		// Apply category filtering
		if useInclude {
			if !includeMap[config.Category] {
				continue // Skip if not in the include list
			}
		} else if useExclude {
			if excludeMap[config.Category] {
				continue // Skip if in the exclude list
			}
		}
		// If no filters or passed filters, proceed

		enabledPatterns++

		re, err := regexp.Compile(config.Regex)
		if err != nil {
			// Log this error? For now, just skip the pattern
			continue
		}

		pm.compiledPatterns[name] = &CompiledPattern{
			Name:        name,
			Description: config.Description,
			Regex:       re,
			Config:      config, // Includes the Category now
		}
	}

	// Critical global exclusions (can be kept simple for now)
	criticalExclusions := []string{
		"example", "sample", "test", "demo",
		"function(", "return",
	}
	pm.exclusionPatterns = make([]*regexp.Regexp, 0)
	for _, exclusion := range criticalExclusions {
		re, err := regexp.Compile(regexp.QuoteMeta(exclusion))
		if err != nil {
			continue
		}
		pm.exclusionPatterns = append(pm.exclusionPatterns, re)
	}

	return nil
}

func (pm *PatternManager) SetLocalMode(enabled bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.localModeEnabled = enabled
}

func (pm *PatternManager) IsLocalModeEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.localModeEnabled
}

func (pm *PatternManager) GetPatternCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.compiledPatterns)
}

/* 
   Returns a copy of all compiled patterns to prevent modification
*/
func (pm *PatternManager) GetCompiledPatterns() map[string]*CompiledPattern {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	patterns := make(map[string]*CompiledPattern, len(pm.compiledPatterns))
	for k, v := range pm.compiledPatterns {
		patterns[k] = v
	}
	
	return patterns
}

/* 
   Adds a new pattern to the manager with specified name, regex and description
*/
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
			MinLength:   8,
			MaxLength:   500,
		},
	}
	
	return nil
}

/* 
   Resets the pattern manager to its initial state
*/
func (pm *PatternManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.compiledPatterns = make(map[string]*CompiledPattern)
	pm.exclusionPatterns = make([]*regexp.Regexp, 0)
	pm.specificExclusions = make(map[string][]*regexp.Regexp)
	pm.localModeEnabled = false
}
