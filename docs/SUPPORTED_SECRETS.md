# Supported Secret Types

SecretHound is equipped with **over 60 patterns** to detect a wide variety of secrets. These patterns are organized into categories, allowing for more targeted scanning when using the `--include-categories` or `--exclude-categories` flags.

Below is a list of supported categories and examples of the types of secrets detected within them. For a complete and up-to-date list of all individual patterns and their details, you can use the command:

```bash
secrethound --list-patterns
```

## Pattern Categories

### Cloud Provider Keys & Tokens
- **AWS**: Access Keys, Secret Keys, S3 URLs (pre-signed, etc.)
- **Google Cloud (GCP)**: API Keys, Service Account Credentials (JSON)
- **Azure**: Service Principal Secrets, Storage Keys
- **Alibaba Cloud**: AccessKey ID, AccessKey Secret

### API Keys (General & SaaS)
- General API Keys (various common formats)
- Stripe API Keys
- Twilio API Keys
- SendGrid API Keys
- Slack Tokens (Bot, User, Webhook)
- GitHub Tokens (Personal Access Tokens, OAuth tokens)
- ... and more SaaS provider keys.

### Authentication & Session Tokens
- Bearer Tokens
- JSON Web Tokens (JWT)
- OAuth Access Tokens
- Basic Auth Credentials (in URLs or headers)
- Session IDs (common patterns)

### Database Credentials
- Database Connection Strings (various formats including user/pass)
- Private Keys often associated with DB auth (e.g., PEM in config)

### Cryptographic Keys
- Generic Private Keys (PEM, OpenSSH format)
- PGP Private Keys
- SSH Private Keys

### Personally Identifiable Information (PII)
- Email Addresses (keyword-dependent)
- Phone Numbers (US format, keyword-dependent)
- IP Addresses (IPv4/IPv6, keyword-dependent with OID exclusions)
- MAC Addresses (keyword-dependent, colon format only)
- US ZIP Codes (keyword-dependent)
- Serial Numbers (keyword-dependent)

### Web3 & Cryptocurrency
- Ethereum Addresses
- Ethereum Private Keys
- Bitcoin Addresses (P2PKH, P2SH, Bech32)
- Bitcoin Private Keys (WIF format)
- Generic Cryptocurrency Private Keys (common hex patterns)

### Network & Infrastructure
- Generic Domain Names / Hostnames
- URLs with potentially sensitive parameters or paths
- Netlify Access Tokens

### Generic & Miscellaneous
- Generic High Entropy Strings (potential secrets)
- Passwords in URLs or common config contexts
- Artifactory Credentials
- npm Tokens

This list is continuously updated. Always refer to `secrethound --list-patterns` for the most current set of patterns and their categories.

> **Note**: Many patterns are now "keyword-dependent", meaning they only match when specific keywords (like `ip_addr`, `mac_address`, `phone`, etc.) are found near the value. This significantly reduces false positives.

## API Keys and Tokens

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Google API Key | Google API key | `AIza[0-9A-Za-z\-_]{35}` |
| Firebase API Key | Firebase API key | `AIzaSy[0-9A-Za-z_-]{33}` |
| Google OAuth | Google OAuth access token | `ya29\.[0-9A-Za-z\-_]+` |
| Google Cloud Platform | Google Cloud Platform API Key | `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` |
| AWS Key | Amazon AWS access key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret | AWS secret access key | `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]` |
| Heroku API Key | Heroku API key | `[h\|H][e\|E][r\|R][o\|O][k\|K][u\|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}` |

## Payment and Financial Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Stripe Secret Key | Stripe standard API key | `sk_live_[0-9a-zA-Z]{24,34}` |
| Stripe Publishable Key | Stripe publishable key | `pk_live_[0-9a-zA-Z]{24,34}` |
| Stripe Test Secret Key | Stripe test secret key | `sk_test_[0-9a-zA-Z]{24,34}` |
| Stripe Test Publishable Key | Stripe test publishable key | `pk_test_[0-9a-zA-Z]{24,34}` |
| Square Access Token | Square OAuth token | `sq0atp-[0-9A-Za-z\-_]{22}` |
| Square OAuth Secret | Square OAuth secret | `sq0csp-[0-9A-Za-z\-_]{43}` |
| PayPal/Braintree Client ID | PayPal/Braintree Client ID (keyword-dependent) | `(?i)(?:paypal\|braintree)[_-]?(?:client[_-]?)?(?:id\|key\|secret)\s*[:=]\s*['"](...)['"` |
| Braintree Token | Braintree access token | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` |

## Email and Communication Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Mailgun API Key | Mailgun API key | `key-[0-9a-zA-Z]{32}` |
| Mailchimp API Key | Mailchimp API key | `[0-9a-f]{32}-us[0-9]{1,2}` |
| SendGrid API Key | SendGrid API key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` |
| Slack Token | Slack token | `xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}` |
| Slack Webhook | Slack webhook URL | `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24,32}` |

## Cloud Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Digital Ocean PAT | Digital Ocean personal access token | `dop_v1_[a-f0-9]{64}` |
| Digital Ocean OAuth Token | Digital Ocean OAuth token | `doo_v1_[a-f0-9]{64}` |
| Digital Ocean Refresh Token | Digital Ocean refresh token | `dor_v1_[a-f0-9]{64}` |
| GitHub PAT | GitHub personal access token | `ghp_[0-9a-zA-Z]{36}` |
| GitHub Personal Token | GitHub personal token | `gh[a-z]_[A-Za-z0-9_]{36,255}` |
| Azure Storage Connection | Azure storage connection string | `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=` |
| Azure SQL Connection | Azure SQL connection string | `Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;` |
| Azure Service Bus | Azure Service Bus connection string | `Endpoint=sb:\/\/[^.]+\.servicebus\.windows\.net\/;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+` |
| Azure CosmosDB | Azure CosmosDB connection string | `AccountEndpoint=https:\/\/[^.]+\.documents\.azure\.com:443\/;AccountKey=[^;]+;` |

## E-commerce Platforms

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Shopify Access Token | Shopify access token | `shpat_[a-fA-F0-9]{32}` |
| Shopify Custom App Token | Shopify custom app access token | `shpca_[a-fA-F0-9]{32}` |
| Shopify Private App Token | Shopify private app access token | `shppa_[a-fA-F0-9]{32}` |
| Shopify Shared Secret | Shopify shared secret | `shpss_[a-fA-F0-9]{32}` |

## Authentication and Security

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Basic Auth | HTTP basic authentication | `(?i)(?:basic\s+)(?:[a-zA-Z0-9\+\/=]{10,100})` |
| Bearer Token | Bearer authentication token | `(?i)bearer\s+[a-zA-Z0-9_\-\.=]{10,500}` |
| JWT Token | JWT token | `eyJ[a-zA-Z0-9_\-\.=]{10,500}` |
| JWT Token (Improved) | JWT token with improved pattern | `eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+` |
| OAuth Token | OAuth token | `(?i)(?:oauth\|access)[._-]?token[.\s\'\"]*[=:][.\s\'\"]*[a-zA-Z0-9_\-\.=]{10,500}` |
| OAuth 2.0 Access Token | OAuth 2.0 access token | `ya29\.[0-9A-Za-z\-_]+` |
| Generic Password | Password in configuration | `(?i)(?:password\|passwd\|pwd\|secret)[\s]*[=:]+[\s]*["']([^'"]{8,30})["']` |
| Authentication Token | Authentication token with comment | `['"]?([a-zA-Z0-9_\-\.]{32,64})['"]?\s*[,;]?\s*\/\/\s*[Aa]uth(?:entication)?\s+[Tt]oken` |
| Private Key Variable | Private key variable (excludes tracking events) | `['"?(?:private_?key\|secret_?key)['"?\s*[:=]\s*['"(...)['"]` |
| Encryption Key | Encryption key | `(?i)['"]?enc(?:ryption)?[_-]?key['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]` |
| Signing Key | Signing key/secret | `(?i)['"]?sign(?:ing)?[_-]?(?:secret\|key)['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/]{16,64})['"]` |

## Database Credentials

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| MongoDB URL | MongoDB connection string | `mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\/]+\/\w+` |
| MongoDB SRV | MongoDB SRV connection string | `mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+\/[^?]+` |
| PostgreSQL URL | PostgreSQL connection string | `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+\/\w+` |
| MySQL URL | MySQL connection string | `mysql:\/\/[^:]+:[^@]+@[^\/]+\/\w+` |
| Redis URL | Redis connection string | `redis(?::\\/\\/)[^:]+:[^@]+@[^\/]+(?::\d+)?` |
| MS SQL Connection String | Microsoft SQL Server connection string | `Server=.+;Database=.+;User (?:ID\|Id)=.+;Password=.+;` |
| Configuration API Key | Configuration API key | `['"]?(?:api\|app)(?:_\|-\|\.)(?:key\|token\|secret)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]` |
| Configuration Secret | Configuration secret | `['"]?(?:secret\|private\|auth)(?:_\|-\|\.)(?:key\|token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]` |

## Private Keys and Certificates

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Private Key Content | Private key with actual key data | `-----BEGIN (?:RSA \|OPENSSH \|...) PRIVATE KEY-----[\s]*[A-Za-z0-9+/=]{20,}` |

## CI/CD and DevOps

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Jenkins API Token | Jenkins API token | `(?i)(?:jenkins\|hudson).{0,5}(?:api)?.{0,5}(?:token).{0,5}['"]([0-9a-zA-Z]{30,})['"]` |
| NPM Access Token | NPM access token | `npm_[A-Za-z0-9]{36}` |
| Docker Hub Personal Access Token | Docker Hub personal access token | `dckr_pat_[A-Za-z0-9_-]{56}` |
| GitLab Runner Token | GitLab runner registration token | `glrt-[0-9a-zA-Z_\-]{20,}` |
| GitLab Personal Token | GitLab personal access token | `glpat-[0-9a-zA-Z_\-]{20,}` |
| Netlify Access Token | Netlify personal access token | `nf[pcfub]_[a-zA-Z0-9_\-]{36}` |

## Generic Secret Patterns

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Generic API Key | Generic API key format | `['"]?(?:api_?key\|api_?secret\|app_?key\|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]` |
| API Key Assignment | API key assignment | `['"]?(?:api_?key\|api_?secret\|app_?key\|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]` |

## PII (Personally Identifiable Information)

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Email Address | Email address (keyword-dependent) | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| Phone Number | Phone number (US format, keyword-dependent) | Requires keywords like `phone`, `mobile`, `tel` |
| IPv4 Address | IPv4 address (keyword-dependent) | Requires keywords like `ip_addr`, `host_addr`, `server_ip` |
| IPv6 Address | IPv6 address (keyword-dependent) | Requires keywords like `ipv6`, `ip6` |
| MAC Address | MAC address (keyword-dependent, colon format) | Requires keywords like `mac_address`, `ethernet_addr`, `hw_addr` |
| US ZIP Code | US ZIP code (keyword-dependent) | Requires keywords like `zip`, `postal`, `postcode` |
