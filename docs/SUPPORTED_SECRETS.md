# Supported Secret Types

SecretHound can detect over 100 different types of secrets and sensitive information across a wide range of platforms and services. This document provides a comprehensive list of the types of secrets that SecretHound can identify.

## API Keys and Tokens

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Google API Key | Google API key | `AIza[0-9A-Za-z\-_]{35}` |
| Firebase API Key | Firebase API key | `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` |
| Google OAuth | Google OAuth access token | `ya29\.[0-9A-Za-z\-_]+` |
| Google OAuth Refresh | Google OAuth refresh token | `1/[0-9A-Za-z\-_]{43}|1/[0-9A-Za-z\-_]{64}` |
| Google Captcha | Google reCAPTCHA key | `6L[0-9A-Za-z-_]{38}` |
| AWS Key | Amazon AWS access key ID | `AKIA[0-9A-Z]{16}` |
| AWS Secret | AWS secret access key | `aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?` |
| OpenAI API Key | OpenAI API key | `sk-[a-zA-Z0-9]{48}` |
| HuggingFace API Key | HuggingFace API key | `hf_[a-zA-Z0-9]{16,64}` |
| Anthropic API Key | Anthropic API key | `sk-ant-[a-zA-Z0-9]{48}` |

## Payment and Financial Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Stripe API Key | Stripe standard API key | `sk_live_[0-9a-zA-Z]{24}` |
| Stripe Restricted Key | Stripe restricted API key | `rk_live_[0-9a-zA-Z]{24}` |
| Stripe Publishable Key | Stripe publishable key | `pk_live_[0-9a-zA-Z]{24}` |
| Stripe Webhook Secret | Stripe webhook secret | `whsec_[a-zA-Z0-9]{32,48}` |
| Square Access Token | Square OAuth token | `sqOatp-[0-9A-Za-z\-_]{22}` |
| Square OAuth Secret | Square OAuth secret | `sq0csp-[0-9A-Za-z\-_]{43}` |
| PayPal Braintree | PayPal Braintree access token | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` |
| Braintree Key | Braintree API key | `braintree[._-]?(?:sandbox\|production)?[._-]?(?:access_token\|access\|token\|private\|public\|merchant\|key\|id\|client\|secret)` |
| Plaid API Key | Plaid API key | `plaid[._-]?(?:sandbox\|production\|development)?[._-]?(?:secret\|key)` |
| Adyen API Key | Adyen API key | `AQE[a-zA-Z0-9]{36}` |
| Coinbase API Key | Coinbase API key | `coinbase[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |

## Email and Communication Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Mailgun API Key | Mailgun API key | `key-[0-9a-zA-Z]{32}` |
| Mailchimp API Key | Mailchimp API key | `[0-9a-f]{32}-us[0-9]{1,2}` |
| SendGrid API Key | SendGrid API key | `SG\.[\w_]{16,32}\.[\w_]{16,64}` |
| Postmark API Key | Postmark API key | `postmark[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |
| Twilio API Key | Twilio API key | `SK[0-9a-fA-F]{32}` |
| Twilio Account SID | Twilio account SID | `AC[a-zA-Z0-9_\-]{32}` |
| Slack Token | Slack token | `xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}` |
| Slack Webhook | Slack webhook URL | `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}` |
| Discord Bot Token | Discord bot token | `(?:N\|M\|O)[a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}` |
| Discord Webhook | Discord webhook URL | `https://(?:ptb.\|canary.)?discord(?:app)?.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]+` |

## Cloud Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| AWS MWS Auth Token | Amazon MWS auth token | `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| AWS URL | Amazon S3 bucket URL | `[a-zA-Z0-9-\._]+\.s3\.amazonaws\.com` |
| Azure Storage Account | Azure storage account URL | `https?:\/\/[a-zA-Z0-9_-]{3,24}\.(?:blob\|file\|table)\.core\.windows\.net\/` |
| Azure SQL Connection String | Azure SQL connection string | `Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+` |
| Digital Ocean PAT | Digital Ocean personal access token | `dop_v1_[a-f0-9]{64}` |
| Dropbox API Key | Dropbox API key | `dropbox[._-]?(?:api\|access)?[._-]?(?:key\|token\|secret)` |
| GitHub PAT | GitHub personal access token | `ghp_[a-zA-Z0-9_]{36}` |
| GitHub PAT v2 | GitHub personal access token v2 | `github_pat_[a-zA-Z0-9_]{82}` |
| Heroku API Key | Heroku API key | `[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}` |
| Alibaba Access Key | Alibaba Cloud access key | `LTAI[a-zA-Z0-9]{20}` |

## Social Media and Marketing

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Facebook Access Token | Facebook access token | `EAACEdEose0cBA[0-9A-Za-z]+` |
| Facebook Client ID | Facebook client ID | `facebook[._-]?(?:api\|client\|app)?[._-]?(?:key\|token\|secret\|id)[\s]*[=:][\s]*["']([0-9]{13,17})["']` |
| Twitter Access Token | Twitter access token | `[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}` |
| Twitter Bearer Token | Twitter bearer token | `AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{37}` |
| LinkedIn Client ID | LinkedIn client ID | `linkedin[._-]?(?:api\|client\|app)?[._-]?(?:key\|token\|secret\|id)` |
| Instagram Access Token | Instagram access token | `IGQ[a-zA-Z0-9_-]{125,200}` |
| Google Analytics ID | Google Analytics tracking ID | `UA-[0-9]{5,}-[0-9]{1,}` |
| Google Measurement ID | Google Analytics 4 measurement ID | `G-[A-Z0-9]{10}` |
| Segment API Key | Segment API key | `segment[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |

## Authentication and Security

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Basic Auth Credentials | HTTP basic authentication | `basic\s*[a-zA-Z0-9+/=:_\+\/-]{16,}` |
| Bearer Token | Bearer authentication token | `bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]{5,100}` |
| JSON Web Token | JWT token | `ey[a-zA-Z0-9]{2,4}\.ey[a-zA-Z0-9\/\\_-]{10,}\.(?:[a-zA-Z0-9\/\\_-]*)` |
| Generic Password | Password in configuration | `(password\|passwd\|pwd\|secret)[\s]*[=:]+[\s]*['"][^'"]{4,30}['"]` |
| Password in URL | Credentials in URL string | `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\\s]` |
| Okta API Key | Okta API key | `okta[._-]?(?:api)?[._-]?(?:key\|token\|secret\|id)` |
| Auth0 API Key | Auth0 API key | `auth0[._-]?(?:api\|client\|app)?[._-]?(?:key\|token\|secret\|id)` |
| OTP Secret | One-time password secret | `otp_secret\s*=\s*['"]([a-zA-Z0-9]{16})['"]` |

## Database Credentials

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| MongoDB URL | MongoDB connection string | `mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?` |
| MongoDB SRV | MongoDB SRV connection string | `mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?` |
| PostgreSQL URL | PostgreSQL connection string | `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?` |
| MySQL URL | MySQL connection string | `mysql:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?` |
| Redis URL | Redis connection string | `redis:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?` |
| Elasticsearch URL | Elasticsearch connection string | `https?:\/\/[^:]+:[^@]+@(?:[a-zA-Z0-9_-]+\.)+(?:us-(?:east\|west)-[0-9]+\|eu-(?:west\|central)-[0-9]+\|ap-(?:southeast\|northeast\|east)-[0-9]+)\.(?:bonsaisearch\|bonsai\.io)` |

## Private Keys and Certificates

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| RSA Private Key | RSA private key | `-----BEGIN RSA PRIVATE KEY-----` |
| DSA Private Key | DSA private key | `-----BEGIN DSA PRIVATE KEY-----` |
| EC Private Key | EC private key | `-----BEGIN EC PRIVATE KEY-----` |
| OpenSSH Private Key | OpenSSH private key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| PGP Private Key | PGP private key block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| PKCS8 Private Key | PKCS8 private key | `-----BEGIN PRIVATE KEY-----` |
| SSH DSS Key | SSH DSS key | `ssh-dss [a-zA-Z0-9/+]+` |
| SSH RSA Key | SSH RSA key | `ssh-rsa [a-zA-Z0-9/+]+` |
| Certificate | X.509 certificate | `-----BEGIN CERTIFICATE-----` |
| Certificate Signing Request | CSR | `-----BEGIN CERTIFICATE REQUEST-----` |

## CI/CD and DevOps

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Jenkins API Token | Jenkins API token | `jenkins[._-]?(?:api)?[._-]?(?:key\|token\|secret\|password)` |
| CircleCI Token | CircleCI token | `circle[._-]?(?:ci\|token\|secret\|password\|credential)` |
| NPM Token | NPM authentication token | `npm[._-]?(?:token\|secret\|password\|credential)` |
| Docker Hub Token | Docker Hub access token | `docker_hub\|dockerhub[._-]?(?:access_token\|token)` |
| Kubernetes Config | Kubernetes configuration token | `kubernetes\|k8s[._-]?(?:config\|token\|secret\|password\|credential)` |
| Datadog API Key | Datadog API key | `datadog[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |
| New Relic API Key | New Relic API key | `NRAK-[A-Z0-9]{27}` |
| Sentry DSN | Sentry data source name | `https?:\/\/[a-zA-Z0-9]+@[a-zA-Z0-9]+\.ingest\.sentry\.io\/[0-9]+` |

## Content Delivery Networks

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Cloudflare API Key | Cloudflare API key | `cloudflare[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |
| Cloudflare API Token | Cloudflare API token | `[a-z0-9]{40,100}` |
| Fastly API Key | Fastly API key | `fastly[._-]?(?:api)?[._-]?(?:key\|token\|secret\|password)` |
| Cloudfront Key Pair ID | AWS CloudFront key pair ID | `cloudfront[._-]?(?:key_pair_id\|keypairid\|key_id)` |

## Machine Learning Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| OpenAI API Key | OpenAI API key | `sk-[a-zA-Z0-9]{48}` |
| HuggingFace API Key | HuggingFace API key | `hf_[a-zA-Z0-9]{16,64}` |
| Cohere API Key | Cohere API key | `cohere[._-]?(?:api)?[._-]?(?:key\|token\|secret)` |
| Anthropic API Key | Anthropic API key | `sk-ant-[a-zA-Z0-9]{48}` |
| Replicate API Key | Replicate API key | `r8_[a-zA-Z0-9]{43,60}` |
| Stability API Key | Stability AI API key | `sk-[a-zA-Z0-9]{20,60}` |
| LangChain API Key | LangChain API key | `ls__[a-zA-Z0-9]{20,100}` |

## Generic Secrets

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Generic API Key | Generic API key format | `(?:api[_-]?(?:key)\|token\|secret)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]` |
| Generic Secret | Generic secret format | `(?:secret\|private[_-]?key\|password)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]` |
| High Entropy String | High entropy strings | `[a-zA-Z0-9_-]{32,100}` |

## Custom Regex Patterns

You can add your own custom regex patterns by creating a file with the following format:

