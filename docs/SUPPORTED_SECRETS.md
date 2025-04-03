# Supported Secret Types

SecretHound can detect over 50 different types of secrets and sensitive information across a wide range of platforms and services. This document provides a comprehensive list of the types of secrets that SecretHound can identify.

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
| PayPal/Braintree | PayPal/Braintree credentials | `(?i)(?:paypal\|braintree).{0,20}['\"][A-Za-z0-9_-]{20,64}['\"]` |
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
| Private Key Variable | Private key variable | `['"]?(?:private_?key\|secret_?key)['"]?\s*[:=]\s*['"]([^'"]{20,})['"]` |
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
| Private Key Content | Private key content | `-----BEGIN (?:RSA\|OPENSSH\|DSA\|EC\|PGP) PRIVATE KEY( BLOCK)?-----` |

## CI/CD and DevOps

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Jenkins API Token | Jenkins API token | `(?i)(?:jenkins\|hudson).{0,5}(?:api)?.{0,5}(?:token).{0,5}['\"]([0-9a-zA-Z]{30,})['\"]` |
| NPM Access Token | NPM access token | `npm_[A-Za-z0-9]{36}` |
| Docker Hub Personal Access Token | Docker Hub personal access token | `dckr_pat_[A-Za-z0-9_-]{56}` |
| GitLab Runner Token | GitLab runner registration token | `glrt-[0-9a-zA-Z_\-]{20,}` |
| GitLab Personal Token | GitLab personal access token | `glpat-[0-9a-zA-Z_\-]{20,}` |

## Generic Secret Patterns

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Generic API Key | Generic API key format | `['"]?(?:api_?key\|api_?secret\|app_?key\|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]` |
| API Key Assignment | API key assignment | `['"]?(?:api_?key\|api_?secret\|app_?key\|app_?secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9_\-\.]{16,64})['"]` |
