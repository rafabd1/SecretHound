# Supported Secret Types

SecretHound can detect a wide range of secrets and sensitive information across different platforms and services. This document provides a comprehensive list of the types of secrets that SecretHound can identify.

## API Keys and Tokens

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Google API Key | Google API key | `AIza[0-9A-Za-z\-_]{35}` |
| Firebase API Key | Firebase API key | `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` |
| Google OAuth | Google OAuth access token | `ya29\.[0-9A-Za-z\-_]+` |
| Google Captcha | Google reCAPTCHA key | `6L[0-9A-Za-z-_]{38}` |
| Stripe API Key | Stripe standard API key | `sk_live_[0-9a-zA-Z]{24}` |
| Stripe Restricted Key | Stripe restricted API key | `rk_live_[0-9a-zA-Z]{24}` |
| Square Access Token | Square OAuth token | `sqOatp-[0-9A-Za-z\-_]{22}` |
| Square OAuth Secret | Square OAuth secret | `sq0csp-[0-9A-Za-z\-_]{43}` |
| PayPal Braintree | PayPal Braintree access token | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` |
| Mailgun API Key | Mailgun API key | `key-[0-9a-zA-Z]{32}` |
| Mailchimp API Key | Mailchimp API key | `[0-9a-f]{32}-us[0-9]{1,2}` |
| Picatic API Key | Picatic API key | `sk_live_[0-9a-z]{32}` |
| Generic API Key | Generic API key format | ``[aA][pP][iI][_]?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]`` |

## Cloud Services

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| AWS Access Key | Amazon AWS access key ID | `AKIA[0-9A-Z]{16}` |
| AWS MWS Auth Token | Amazon MWS auth token | `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| AWS URL | Amazon S3 bucket URL | `[a-zA-Z0-9-\._]+\.s3\.amazonaws\.com` |
| GCP API Key | Google Cloud Platform API key | `AIza[0-9A-Za-z\-_]{35}` |
| GCP OAuth | Google Cloud Platform OAuth | `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` |
| GCP Service Account | Google service account file | `"type": "service_account"` |
| Heroku API Key | Heroku API key | ``[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`` |

## Social Media and Communication

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Facebook Access Token | Facebook access token | `EAACEdEose0cBA[0-9A-Za-z]+` |
| Facebook OAuth | Facebook OAuth | ``[fF][aA][cC][eE][bB][oO][oO][kK].*['"][0-9a-f]{32}['"]`` |
| Twitter Access Token | Twitter access token | ``[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`` |
| Twitter OAuth | Twitter OAuth | ``[tT][wW][iI][tT][tT][eE][rR].*['"][0-9a-zA-Z]{35,44}['"]`` |
| Twitter Bearer Token | Twitter bearer token | `AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{37}` |
| Slack Token | Slack token | `xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}` |
| Slack Webhook | Slack webhook URL | `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}` |
| Twilio API Key | Twilio API key | `SK[0-9a-fA-F]{32}` |
| Twilio Account SID | Twilio account SID | `AC[a-zA-Z0-9_\-]{32}` |
| Twilio App SID | Twilio app SID | `AP[a-zA-Z0-9_\-]{32}` |

## Authentication Credentials

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Basic Auth Credentials | HTTP basic authentication | `(?i)basic\s*[a-zA-Z0-9+/=:_\+\/-]{16,}` |
| Bearer Token | Bearer authentication token | `bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]{5,100}` |
| JSON Web Token | JWT token | `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$` |
| Generic Password | Password in configuration | `(?i)(password\|passwd\|pwd\|secret)[\s]*[=:]+[\s]*['"][^'"]{4,30}['"]` |
| Password in URL | Credentials in URL string | `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\\s]` |

## Private Keys and Certificates

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| RSA Private Key | RSA private key | `-----BEGIN RSA PRIVATE KEY-----` |
| DSA Private Key | DSA private key | `-----BEGIN DSA PRIVATE KEY-----` |
| EC Private Key | EC private key | `-----BEGIN EC PRIVATE KEY-----` |
| PGP Private Key | PGP private key block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| SSH Private Key | SSH private key | `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)` |

## Repository and Version Control

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| GitHub Access Token | GitHub access token | `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*` |
| GitHub Token | GitHub token or key | ``[gG][iI][tT][hH][uU][bB].*['"][0-9a-zA-Z]{35,40}['"]`` |

## Generic Secrets

| Secret Type | Description | Example Pattern |
|-------------|-------------|-----------------|
| Generic Secret | Generic secret format | ``[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]`` |
| High Entropy String | High entropy strings | Complex pattern |

## Custom Regex Patterns

You can add your own custom regex patterns by creating a file with the following format:

