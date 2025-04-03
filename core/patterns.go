package core

// RegexPatterns contains all regex patterns for detecting secrets
var RegexPatterns = map[string]string{
	// API Keys
	"aws_key":               `AKIA[0-9A-Z]{16}`,
	"aws_secret":            `(?i)aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?['\"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]`,
	"google_api":            `AIza[0-9A-Za-z\-_]{35}`,
	"google_oauth":          `ya29\.[0-9A-Za-z\-_]+`,
	"google_cloud_platform": `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"google_captcha":        `(?i)(?:recaptcha|captcha)(?:_|-|\.|site|key)(?:key|token|site)?[\s]*(?:=|:)[\s]*(?:["'])(6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39})["']`,
	"google_oauth_refresh":  `(?i)(?:refresh_token|oauth_token)[._-]?[\s]*[=:]+[\s]*["']1/[0-9A-Za-z\-_]{43,64}["']|["']1/[0-9A-Za-z\-_]{43,64}["'][\s]*[:=]+[\s]*(?:true|false|raw)`,
	"firebase":              `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"firebase_config":       `(?i)firebaseio\.com.*?["']?(?:auth|secret|key)["']?\s*[:=]\s*["']([^"']+)["']`,

	// Payment Processors
	"stripe_api_key":         `sk_live_[0-9a-zA-Z]{24}`,
	"stripe_restricted_key":  `rk_live_[0-9a-zA-Z]{24}`,
	"stripe_publishable_key": `pk_live_[0-9a-zA-Z]{24}`,
	"stripe_test_key":        `sk_test_[0-9a-zA-Z]{24}`,
	"stripe_webhook_secret":  `whsec_[a-zA-Z0-9]{32,48}`,
	"square_access_token":    `sqOatp-[0-9A-Za-z\-_]{22}`,
	"square_oauth_secret":    `sq0csp-[0-9A-Za-z\-_]{43}`,
	"paypal_braintree":       `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"braintree_key":          `(?i)braintree[._-]?(?:sandbox|production)?[._-]?(?:access_token|access|token|private|public|merchant|key|id|client|secret)(?:[._-]?id)?[^0-9A-Za-z]*["\']?([0-9a-zA-Z]{32})["\']?`,
	"plaid_client_id":        `client_id["\s]*(?::|=>|=)[\s]*["']([a-zA-Z0-9]{24})["']`,
	"plaid_secret":           `(?i)plaid[._-]?(?:sandbox|production|development)?[._-]?(?:secret|key)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{32})["']`,
	"plaid_access_token":     `access-(?:sandbox|production|development)-[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}`,
	"adyen_api_key":          `AQE[a-zA-Z0-9]{36}`,
	"adyen_client_key":       `(?i)adyen[._-]?(?:client|public|api|checkout)[._-]?(?:key|token|id)[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{40,50})["']`,
	"coinbase_api_key":       `(?i)coinbase[._-]?(?:api)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{16,64})["']`,
	"coinbase_versioned_key": `(?i)(?:coinbase)[._-]?(?:api|token|key|secret)[\s]*[=:]+[\s]*['"]([0-9a-zA-Z]{64})['"]`,
	"chargify_api_key":       `chrgfy-[a-zA-Z0-9]{43}`,
	"fastspring_api_key":     `(?i)(?:fastspring)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)(?:[_-]?id)?['\"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{10,40}['"]`,

	// Email Services
	"mailgun_api_key":        `key-[0-9a-zA-Z]{32}`,
	"mailchimp_api_key":      `[0-9a-f]{32}-us[0-9]{1,2}`,
	"mailchimp_access_token": `(?i)mailchimp[._-]?(?:api)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9-]{32})["']`,
	"sendgrid_api_key":       `SG\.[\w_]{16,32}\.[\w_]{16,64}`,
	"postmark_api_key":       `(?i)postmark[._-]?(?:api)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9-]{32,36})["']`,
	"sendinblue_api_key":     `xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}`,
	"mandrill_api_key":       `(?i)mandrill[._-]?(?:api)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{22})["']`,
	"zoho_mail_key":          `(?i)zoho[._-]?(?:mail|email)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{32,48})["']`,

	// Cloud Services
	"aws_mws_auth_token":      `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"aws_url":                 `[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com`,
	"aws_s3_url":              `s3:\/\/[a-zA-Z0-9-\.\_]+`,
	"azure_storage_account":   `https?:\/\/[a-zA-Z0-9_-]{3,24}\.(?:blob|file|table)\.core\.windows\.net\/`,
	"azure_subscription_key":  `(?i)azure[._-]?(?:subscription|storage|service)[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9/+]{43}=)["']`,
	"azure_sq_auth_key":       `(?i)(?:azure|sq_auth)(?:_|-|\.)?(?:key|token|secret)(?:[_-]?id)?['\"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{32,64}['"]`,
	"azure_sql_conn_string":   `(?i)Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;`,
	"cloudinary_url":          `cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9_-]{30,35}@[a-zA-Z0-9_-]+`,
	"cloudinary_basic_auth":   `(?i)cloudinary[._-]?(?:api|url)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([0-9a-zA-Z:@]+)["']`,
	"digitalocean_access_key": `(?i)digitalocean[._-]?(?:api|access)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{64})["']`,
	"digitalocean_pat":        `dop_v1_[a-f0-9]{64}`,
	"dropbox_api_key":         `(?i)dropbox[._-]?(?:api|access)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{15,150})["']`,
	"dropbox_short_token":     `sl\.[a-zA-Z0-9_-]{130,145}`,
	"dropbox_long_token":      `(?i)(?:dropbox)[._-]?(?:token|access|auth)[._-]?(?:key|secret)?[\s]*[=:]+[\s]*['"]([a-zA-Z0-9_-]{130,150})['"]`,
	"github_pat":              `ghp_[a-zA-Z0-9_]{36}`,
	"github_pat_v2":           `github_pat_[a-zA-Z0-9_]{82}`,
	"gcp_api_key":             `AIza[a-zA-Z0-9_-]{35}`,
	"gcp_credentials":         `(?:"|')(?:type|project_id|private_key_id|private_key|client_email|client_id|auth_uri|token_uri|auth_provider_x509_cert_url|client_x509_cert_url)(?:"|')\s*:\s*(?:"|')(?!.*(?:example|test|sample|placeholder))`,
	"heroku_api_key":          `(?i)heroku[\-_]?api[\-_]?key|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}`,
	"alibaba_access_key":      `LTAI[a-zA-Z0-9]{20}`,
	"alibaba_secret_key":      `(?i)alibaba[._-]?(?:cloud|aliyun)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9/+=]{30})["']`,

	// Social Media and Communication
	"facebook_access_token": `EAACEdEose0cBA[0-9A-Za-z]+`,
	"facebook_client_id":    `(?i)facebook[._-]?(?:api|client|app)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([0-9]{13,17})["']`,
	"facebook_client_secret": `(?i)facebook[._-]?(?:api|client|app)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-f0-9]{32})["']`,
	"twitter_access_token":   `(?i)[t]w[i]t[t]e[r].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	"twitter_bearer_token":   `AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{37}`,
	"twitter_api_key":        `(?i)twitter[._-]?(?:api)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{25,30})["']`,
	"slack_token":            `xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
	"slack_webhook":          `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
	"slack_workflow_webhook": `https:\/\/hooks\.slack\.com\/workflows\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+`,
	"discord_bot_token":      `(?:N|M|O)[a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}`,
	"discord_webhook":        `https://(?:ptb.|canary.)?discord(?:app)?.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]+`,
	"discord_client_secret":  `(?i)discord[._-]?(?:api|client|bot)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{32})["']`,
	"linkedin_client_id":     `(?i)linkedin[._-]?(?:api|client|app)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{14})["']`,
	"linkedin_client_secret": `(?i)linkedin[._-]?(?:api|client|app)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{16})["']`,
	"instagram_access_token": `IGQ[a-zA-Z0-9_-]{125,200}`,

	// Communication Services
	"twilio_api_key":      `SK[0-9a-fA-F]{32}`,
	"twilio_auth_token":   `(?i)twilio[._-]?(?:api|app|account)?[._-]?(?:key|token|secret|sid|id|auth_token)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32})["']`,
	"nexmo_api_key":       `(?i)nexmo[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{8})["']`,
	"nexmo_api_secret":    `(?i)nexmo[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{16})["']`,
	"vonage_api_key":      `(?i)vonage[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{8})["']`,
	"messagebird_api_key": `(?:(?:production|live)_)?[a-zA-Z0-9]{25}(?![a-zA-Z0-9_])`,
	"infobip_api_key":     `(?i)infobip[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32,50})["']`,
	"sinch_api_key":       `(?i)sinch[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32,64})["']`,

	// Authentication Credentials
	"basic_auth":          `(?i)(?:authorization:\s*|auth:\s*|token:\s*|apikey:\s*|api-key:\s*|'authorization':\s*|"authorization":\s*)basic\s+([a-zA-Z0-9+/=]{5,100})`,
	"basic_auth_detailed": `(?i)(?:\bbasic\s+)([a-zA-Z0-9+/=]{16,})(?!\s+multilingual|\s+latin|\s+plane|\s+support|\s+block|\s+format)`,
	"bearer_token":        `(?i)(?:bearer\s+)([a-zA-Z0-9_\-\.\+\/=]{16,})(?![a-zA-Z0-9_\-\.=:])`,
	"jwt_token":           `(?i)(?:ey[a-zA-Z0-9]{2,4}\.ey[a-zA-Z0-9\/\\_-]{10,}\.(?:[a-zA-Z0-9\/\\_-]*))`,
	"oauth_token":         `(?i)(?:oauth[._-]?token|access[._-]?token)[\s]*[=:]+[\s]*["']([a-zA-Z0-9_\-\.]{30,})["']|["']([a-zA-Z0-9]{40,})["'][\s]*[:=]+[\s]*(?:oauth|token|true|false)`,
	"generic_password":    `(?i)(?:password|passwd|pwd|secret)[\s]*[=:]+[\s]*['"]([^'"]{8,30})['"](?!\s+(?:does|don|isn|doesn|match|valid|must))`,
	"password_in_url":     `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}['"\s]`,
	"otp_secret":          `otp_secret\s*=\s*['"]([a-zA-Z0-9]{16})['"]`,
	"okta_api_key":        `(?i)okta[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{40})["']`,
	"auth0_api_key":       `(?i)auth0[._-]?(?:api|client|app)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{32,100})["']`,
	"auth0_client_secret": `(?i)auth0[._-]?(?:client|app)?[._-]?(?:secret|key)[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{43})["']`,
	"saml_assertion":      `<ds:X509Certificate>([a-zA-Z0-9/+=]{64,512})</ds:X509Certificate>`,

	// Database Credentials
	"mongodb_url":         `mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?`,
	"mongodb_srv":         `mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?`,
	"postgres_url":        `postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?`,
	"mysql_url":           `mysql:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?`,
	"mysql_config":        `(?i)(?:mysql|mariadb)[._-]?(?:database|host|port|user|password|pass|pwd)[\s]*[=:][\s]*["'](.*?)["']`,
	"redis_url":           `redis:\/\/[^:]+:[^@]+@[^\/]+(?:\/[^\"\'\s]+)?`,
	"redis_pw_pattern":    `(?i)(?:redis)[._-]?(?:password|pass|pwd)[\s]*[=:][\s]*["'](.*?)["']`,
	"cassandra_auth":      `(?i)(?:cassandra)[._-]?(?:password|pass|pwd)[\s]*[=:][\s]*["'](.*?)["']`,
	"elasticsearch_url":   `(?i)https?:\/\/[^:]+:[^@]+@(?:[a-zA-Z0-9_-]+\.)+(?:us-(?:east|west)-[0-9]+|eu-(?:west|central)-[0-9]+|ap-(?:southeast|northeast|east)-[0-9]+)\.(?:bonsaisearch|bonsai\.io)`,
	"dynamodb_config":     `(?i)(?:dynamodb)[._-]?(?:accesskey|secretkey|region)[\s]*[=:][\s]*["'](.*?)["']`,
	"firebase_db_key":     `(?i)https:\/\/[a-zA-Z0-9_-]+\.firebaseio\.com.*?(?:authSecret|secret|key)[\s]*[=:][\s]*["'](.*?)["']`,

	// Private Keys and Certificates
	"rsa_private_key":     `-----BEGIN RSA PRIVATE KEY-----`,
	"dsa_private_key":     `-----BEGIN DSA PRIVATE KEY-----`,
	"ec_private_key":      `-----BEGIN EC PRIVATE KEY-----`,
	"openssh_private_key": `-----BEGIN OPENSSH PRIVATE KEY-----`,
	"pgp_private_key":     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"pem_key":             `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
	"pkcs8_key":           `-----BEGIN PRIVATE KEY-----`,
	"pkcs8_encrypted":     `-----BEGIN ENCRYPTED PRIVATE KEY-----`,
	"ssh_dss_key":         `ssh-dss [a-zA-Z0-9/+]+`,
	"ssh_rsa_key":         `ssh-rsa [a-zA-Z0-9/+]+`,
	"certificate":         `-----BEGIN CERTIFICATE-----`,
	"certificate_signing": `-----BEGIN CERTIFICATE REQUEST-----`,
	"pgp_public_key":      `-----BEGIN PGP PUBLIC KEY BLOCK-----`,

	// Repository and Version Control
	"github_access_token": `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`,
	"github_oauth_token":  `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com`,
	"github_app_token":    `(?i)(?:github)(?:_|-|\.)(?:application)?(?:_|-|\.)?(?:id|secret|token|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{10,73}['"\s]*[\n,;]`,
	"gitlab_token":        `(?i)(?:gitlab)(?:_|-|\.)(?:application)?(?:_|-|\.)?(?:id|secret|token|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,63}['"\s]*[\n,;]`,
	"bitbucket_client_id": `(?i)(?:bitbucket)(?:_|-|\.)(?:application|app)?(?:_|-|\.)?(?:id|key)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,44}['"\s]*[\n,;]`,
	"bitbucket_secret":    `(?i)(?:bitbucket)(?:_|-|\.)(?:application|app)?(?:_|-|\.)?(?:secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{30,60}['"\s]*[\n,;]`,
	"circleci_token":      `(?i)(?:circle)(?:_|-|\.)(?:ci|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{40,74}['"\s]*[\n,;]`,
	"npm_token":           `(?i)(?:npm)(?:_|-|\.)(?:token|secret|password|credential)['"\s=:]+(?-i)(?:npm_)[a-zA-Z0-9_-]{32,72}['"\s]*[\n,;]`,
	"travis_token":        `(?i)(?:travis)(?:_|-|\.)(?:token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,72}['"\s]*[\n,;]`,

	// Analytics and Tracking
	"google_analytics_id":          `UA-[0-9]{5,}-[0-9]{1,}`,
	"google_measurement_id":        `(?i)(?:google_measurement_id|gtag|gtm_id|ga_tracking_id)[\s]*[=:]+[\s]*["']G-[A-Z0-9]{10}["']|dataLayer\.push\([\s\S]{0,50}["']G-[A-Z0-9]{10}["']`,
	"segment_api_key":              `(?i)(?:segment)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,72}['"\s]*[\n,;]`,
	"amplitude_api_key":            `(?i)(?:amplitude)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,72}['"\s]*[\n,;]`,
	"mixpanel_project_token":       `(?i)(?:mixpanel)(?:_|-|\.)(?:api|project)?(?:_|-|\.)?(?:key|token|id)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"matomo_auth_token":            `(?i)(?:matomo)(?:_|-|\.)(?:auth)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"fullstory_api_key":            `(?i)(?:fullstory)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"piwik_auth_token":             `(?i)(?:piwik)(?:_|-|\.)(?:auth)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,

	// Content Delivery Networks
	"cloudflare_api_key":        `(?i)(?:cloudflare)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,50}['"\s]*[\n,;]`,
	"cloudflare_api_token":      `(?i)(?:cloudflare|cf)[\s\-_\.]*(?:token|key|secret)[\s\-_\.]*(?:=|:|\s=>|\s->)?\s*["\']([a-zA-Z0-9_\-]{40,90})["\']`,
	"akamai_api_key":            `(?i)(?:akamai)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret|id|credential|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{10,72}['"\s]*[\n,;]`,
	"fastly_api_key":            `(?i)(?:fastly)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,72}['"\s]*[\n,;]`,
	"imperva_api_key":           `(?i)(?:imperva)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret|id|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,72}['"\s]*[\n,;]`,
	"cloudfront_key_pair_id":    `(?i)(?:cloudfront)(?:_|-|\.)(?:key_pair_id|keypairid|key_id)['"\s=:]+(?-i)(?:APKA)[A-Z0-9]{16}(['"\s]|\Z)`,
	"cloudfront_private_key":    `-----BEGIN RSA PRIVATE KEY-----[^-]*KEY-----(,|}|]|\s+")`,

	// Machine Learning Services
	"openai_api_key":       `sk-[a-zA-Z0-9]{48}`,
	"huggingface_api_key":  `hf_[a-zA-Z0-9]{16,64}`,
	"cohere_api_key":       `(?i)(?:cohere)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{30,60}['"\s]*[\n,;]`,
	"anthropic_api_key":    `sk-ant-[a-zA-Z0-9]{48}`,
	"replicate_api_key":    `r8_[a-zA-Z0-9]{43,60}`,
	"stability_api_key":    `sk-[a-zA-Z0-9]{20,60}`,
	"langchain_api_key":    `ls__[a-zA-Z0-9]{20,100}`,

	// CI/CD and DevOps
	"jenkins_api_token":       `(?i)(?:jenkins)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,64}['"\s]*[\n,;]`,
	"jenkins_secret_token":    `(?i)(?:jenkins)(?:_|-|\.)(?:secret)?(?:_|-|\.)?(?:key|token|secret|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{30,100}['"\s]*[\n,;]`,
	"docker_hub_password":     `(?i)(?:docker_hub|dockerhub)(?:_|-|\.)(?:token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,100}['"\s]*[\n,;]`,
	"docker_hub_access_token": `(?i)(?:docker_hub|dockerhub)(?:_|-|\.)(?:access_token|token)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,100}['"\s]*[\n,;]`,
	"kubernetes_config":       `(?i)(?:kubernetes|k8s)(?:_|-|\.)(?:config|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{25,100}['"\s]*[\n,;]`,
	"argo_api_token":          `(?i)(?:argo)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret|password)['"\s=:]+(?-i)[a-zA-Z0-9_-]{40,100}['"\s]*[\n,;]`,
	"datadog_api_key":         `(?i)(?:datadog)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,40}['"\s]*[\n,;]`,
	"new_relic_api_key":       `NRAK-[A-Z0-9]{27}`,
	"new_relic_license_key":   `(?i)(?:new_relic|nr)[._-]?(?:license|account)?[._-]?(?:key|token|id)[\s]*[=:]+[\s]*['"]([a-f0-9]{40})['"]`,
	"new_relic_insights_key":  `(?i)(?:insights)?(?:_|-|\.)?(?:insert)?(?:_|-|\.)(?:key|api_key)['"\s=:]+(?-i)[a-zA-Z0-9_-]{16,40}['"\s]*[\n,;]`,
	"npm_access_token":        `(?i)(?:npm)(?:_|-|\.)(?:access_token|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{40,100}['"\s]*[\n,;]`,
	"sentry_access_token":     `(?i)(?:sentry)(?:_|-|\.)(?:access_token|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,100}['"\s]*[\n,;]`,
	"sentry_dsn":              `https?:\/\/[a-zA-Z0-9]+@[a-zA-Z0-9]+\.ingest\.sentry\.io\/[0-9]+`,

	// Generic Secrets
	"generic_api_key":     `(?i)(?:api[_-]?(?:key)|token|secret)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]`,
	"generic_secret":      `(?i)(?:secret|private[_-]?key|password)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]`,
}

// ExclusionPatterns contains regex patterns to exclude (common false positives)
var ExclusionPatterns = []string{
	// Test/example/placeholder keys
	`(?i)(test|example|placeholder|invalid|dummy|sample|demo|fake)(_|-|\.)?([A-Za-z0-9_-]{5,})`,
	`XXXX[A-Za-z0-9_-]{5,}`,
	`00000[A-Za-z0-9_-]{5,}`,
	`RANDOM[A-Za-z0-9_-]{5,}`,
	`(?i)your-?key-?here`,
	`AKIAIOSFODNN7EXAMPLE`,
	
	// Placeholder keys for different services
	`sk_test_[A-Za-z0-9_-]+`, // Stripe test keys
	`sk_live_00000[A-Za-z0-9_-]+`, // Stripe fake live keys
	`(?i)(AAAA)+(BBBB)+(CCCC)+(DDDD)+`, // Base64 placeholder pattern
	
	// Common non-credential patterns
	`(?i)var[A-Za-z0-9_-]{10,}`, // Variable declarations
	`(?i)function[A-Za-z0-9_-]{10,}`, // Function declarations
	`<svg(.+?)>(.+?)</svg>`, // SVG content can contain high entropy strings
	`<path(.+?)d="[^"]+"(.+?)/>`, // SVG path data
	
	// Generic placeholder constants
	`(?i)TO_BE_REPLACED`,
	`(?i)INSERT_[A-Za-z0-9_-]+_HERE`,
	`(?i)YOUR_[A-Za-z0-9_-]+_HERE`,
	`(?i)CHANGE_[A-Za-z0-9_-]+`,
	`(?i)REPLACE_[A-Za-z0-9_-]+`,

	// JavaScript code patterns
	`function\s*\(`,
	`\)\s*{`,
	`\s*var\s+`,
	`\s*const\s+`,
	`\s*let\s+`,
	`console\.log`,
	`module\.exports`,
	`require\(`,
	`import\s+`,
	`export\s+`,
	`return\s+`,
	`if\s*\(`,
	`else\s*{`,
	`for\s*\(`,
	`while\s*\(`,
	`switch\s*\(`,
	`case\s+`,
	`break;`,
	`continue;`,
	`default:`,
	
	// Specific for minified code
	`function\([\w,\s]*\){\s*`,
	`\[native code\]`,
	`window\.`,
	`document\.`,
	
	// base64
	`base64`,
	`data:image/`,
	`font-face`,
	`@charset`,
	`\*\s*/\s*{`,
	
	// CSS Selectors
	`\.css`,
	`#[a-zA-Z][a-zA-Z0-9_-]*\s*{`,
	`\.[a-zA-Z][a-zA-Z0-9_-]*\s*{`,
	`\[[a-zA-Z][a-zA-Z0-9_-]*\]`,
	
	// Common JavaScript patterns
	`function\(t,e`,
	`function\(e,t`,
	`return[a-z]&&`,
	`\?[a-z]\.`,
	`:[a-z]\.`,

	// Additional exclusions for CSS properties
	`--[a-zA-Z0-9_-]+-(background|color|border|shadow|width|height|margin|padding|radius|distance|opacity|blur)`,
	`(width|height|margin|padding|radius|distance|opacity|blur)-(x|y|color|width|height)`,
	
	// Additional exclusions for HTML/CSS/JS
	`origin-trial`,
	`(?i)(insufficient|authentication|insufficient_authentication)`,
	`(?i)(button|modal|tooltip|patterns)-(primary|secondary|hover|background|border|color)`,
	
	// Exclude common JS reserved metadata
	`__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED`,
	`unstable_[a-zA-Z]+`,
	
	// Additional browser/protocol metadata
	`eyJvcmlnaW4i`, // Common base64 prefix in browser origin tokens

	// UI components and labels
	`(?i)(?:children|autoComplete|placeholder|label|title)\s*(?::|=)[\s\w]*["']bearer[\s-]*token["']`,
	`(?i)Bearer[\s-]Token`,
	
	// JavaScript/React specific patterns
	`(?i)UNSAFE_[a-zA-Z_]+`,
	`(?i)__UNSAFE`,
	`(?i)freshchat_[a-zA-Z_]+`,
	`(?i)enable[A-Z][a-zA-Z]+[A-Z][a-zA-Z]+`,
	
	// UUID patterns that aren't secrets
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	
	// Separators and code comments
	`[-]{5,}`,
	
	// Repetitive patterns in minified code - improved more specific versions
	`[NL1]{10,}`,
	`[a-z]{1,2}[A-Z]{1,2}[a-z]{5,}`,
	`[mrnb]{5,}[mrnb]{5,}`,
	
	// Base64 specific patterns that aren't secrets (origin trials, etc)
	`eyJ[a-zA-Z0-9_\-\.]+(?:=*)`,

	// MIME types and content types (common false positives)
	`application/[a-zA-Z0-9_\.\-]+`,
	`text/[a-zA-Z0-9_\.\-]+`,
	`image/[a-zA-Z0-9_\.\-]+`,
	`audio/[a-zA-Z0-9_\.\-]+`,
	`video/[a-zA-Z0-9_\.\-]+`,
	
	// Common file paths and URLs
	`(?i)(?:http|https)://[a-zA-Z0-9_\.\-]+/[a-zA-Z0-9_/\.\-]+`,
	`node_modules/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+`,
	`./node_modules/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+`,

	// Exclusões adicionais para evitar detecção em arquivos de tradução/internacionalização
	`(?i)_(?:chart|msg|flash|trend|enabled|disabled)["'\s:}]`,
	`(?i)i18n`,
	`(?i)translation`,
	`(?i)localization`,
	`(?i)locale`,

	// Adicionar padrões para excluir sequências numéricas repetitivas (como encontradas nos falsos positivos)
	`[0-9]{1}(?:\1+){10,}`,  // Números repetidos como 111111 ou 777777
	`(?:[0-9]{2})\1{5,}`,    // Padrões como 1212121212...
	`(?:[01]{8})\1{2,}`,     // Sequências de bits repetitivas como 01010101...
	
	// Padrões para excluir strings em arquivos minificados
	`(?:[A-Z]{1}[a-zA-Z0-9]{1,3}){20,}`,  // Sequências de identificadores curtos como AC4E1D3GB2...
	
	// Excluir comentários de documentação e texto Unicode
	`Basic\s+Multilingual\s+Plane`,  // Referência ao Unicode BMP
	`(?i)surrogate\s+pairs?`,        // Referência a códigos surrogate do Unicode
	
	// Excluir variáveis e constantes em código minificado
	`[a-zA-Z][0-9][a-zA-Z][0-9]{2,}(?![a-z]{3,})`,  // Padrões como A4B12C em código minificado
	
	// Excluir padrões de zonas de tempo/dados geográficos (como vistos nos falsos positivos)
	`(?:Africa|America|Asia|Europe|Pacific)/[A-Za-z]+\|[A-Z]{3,4}`,  // Referências a fusos horários

	// Adicionar novos padrões de exclusão para códigos de JavaScript minificado
	`(?:[A-Z]{1}[a-z][0-9][A-Z][a-z][0-9]){3,}`,  // Padrões como AaBbCc123
	`(?:["']\d+[A-Za-z]+\d+[A-Za-z]+["'])`,       // Strings como "123Ab456Cd"
	
	// Excluir padrões de código que parecem OAuth tokens
	`['"][a-zA-Z0-9!@]{1,5}[a-zA-Z]+\d+['"]`,     // Strings curtas de código como "AAAA123"
	
	// Identificadores G- em código minificado que não são do Google Analytics
	`G-\d{1,2}[A-Z]{1,3}\d{1,2}[A-Z]{1,3}\d{1,3}`,  // Padrões como G-12AB34CD5 em variáveis
}

// SpecificExclusions é um mapa de exclusões específicas para cada padrão de regex
var SpecificExclusions = map[string][]string{
	"amazon_aws_url": {
		`selectors`,
		`css3-selectors`,
		`REC-css3-selectors`,
		`w3.org/TR`,
	},
	"possible_credentials": {
		`function\s*\(`,
		`\)\s*{`,
		`return`,
		`var\s+`,
		`if\s*\(`,
		`else\s*{`,
		`password:true`,
		`password:!0`,
		`password:null`,
		`password:\s*true`,
		`password:\s*!0`,
		`password:\s*null`,
	},
	"generic_secret": {
		`SECRET_INTERNALS_DO_NOT_USE`,
		`UNSAFE_`,
		`DEPRECATED_`,
		`getSecret`,
		`setSecret`,
		`createSecret`,
		`isSecret`,
		`_secret_`,
	},
	"twilio_account_sid": {},
	"twilio_app_sid": {},
	"twilio_api_key": {
		`base64`,
		`charset`,
		`styles`,
		`background`,
		`data:`,
		`font-face`,
		`@font-face`,
		`eJy`,
		`AAA`,
		`content:`,
		`width:`,
		`height:`,
		`margin:`,
		`padding:`,
	},
	"heroku_api_key": {
		`target`,
		`id:`,
		`element`,
		`appliesTo`,
		`styleBlockIds`,
		`targets:`,
		`selector`,
		`transformers`,
		`uuid`,
		`guid`,
	},
	"authorization_basic": {
		`chart`,
		`content`,
		`settings`,
		`information`,
		`features`,
		`basic\s+[a-z]+$`,  
		`basic\s+\w+\s+\w+`,
	},
	"authorization_api": {
		`api_language`,
		`api_location`,
		`api\s+fails`,
		`api\s+error`,
		`api\s+request`,
		`location\s+api`,
		`using\s+api`,
		`rest\s+api`,
		`graphql\s+api`,
		`webhook\s+api`,
	},
	"aws_key": {
		`AKIAIOSFODNN7EXAMPLE`,
		`AKIAJ[A-Z0-9]{16}EXAMPLE`,
	},
	"generic_api_key": {
		`(?i)api_key["']?\s*[:,]\s*["']YOUR_API_KEY["']`,
		`(?i)api_key["']?\s*[:,]\s*["']DEMO_KEY["']`,
	},
	"high_entropy_string": {
		`[a-f0-9]{32}\.png`,
		`[a-f0-9]{32}\.jpe?g`,
		`[a-f0-9]{32}\.gif`,
		`[a-f0-9]{32}\.svg`,
		`[a-f0-9]{32}\.webp`,
		`[a-f0-9]{32,40}\.min\.(js|css)`,
		`pk_live_[0-9a-zA-Z]{24}`,
		`sk_live_[0-9a-zA-Z]{24}`,
		`sk_test_[0-9a-zA-Z]{24}`,
		`pk_test_[0-9a-zA-Z]{24}`,
		`AIza[0-9A-Za-z\-_]{35}`,
		`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}`,
		`GOCSPX-[a-zA-Z0-9_-]{20,30}`,
		`api_key_[a-zA-Z0-9]{20,40}`,
		`admin_api_[a-zA-Z0-9]{20,40}`,
		`tr_sec_[a-zA-Z0-9]{20,40}`,
		`[a-zA-Z]{10,20}(Token|Secret|Key)[a-zA-Z0-9]{5,30}`,
		`npm_[a-zA-Z0-9_]{10,60}`,
		`node_[a-zA-Z0-9_]{10,60}`,
		`react_[a-zA-Z0-9_]{10,60}`,
		`angular_[a-zA-Z0-9_]{10,60}`,
		`vue_[a-zA-Z0-9_]{10,60}`,
		`github_pat_[a-zA-Z0-9_]{60,90}`,
		`ghp_[a-zA-Z0-9]{36}`,
		`gho_[a-zA-Z0-9]{36}`,
		`--[a-z0-9_-]+-[a-z0-9_-]+`,
		`width`,
		`height`,
		`margin`,
		`border`,
		`padding`,
		`color`,
		`background`,
		`shadow`,
		`hover`,
		`opacity`,
		`distance`,
		`backdrop`,
		`modal`,
		`tooltip`,
		`insufficient`,
		`authentication`,
		`unstable_`,
		`__SECRET_INTERNALS`,
		`enableClient`,
		`distance-x`,
		`distance-y`,
		`shadow-blur`,
		`shadow-color`,
		`origin-trial`,
		`UNSAFE_`,
		`__UNSAFE`,
		`freshchat_`,
		`enable[A-Z][a-zA-Z]+`,
		`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
		`^-{5,}$`,
		`application/x-www-form-urlencoded`,
		`application/json`,
		`application/xml`,
		`application/javascript`,
		`application/octet-stream`,
		`multipart/form-data`,
		`node_modules/core-js/modules/`,
		`node_modules/webpack/`,
		`node_modules/babel/`,
		`node_modules/react/`,
		`node_modules/angular/`,
		`node_modules/vue/`,
		`node_modules/jquery/`,
		`node_modules/lodash/`,
		`documentation\.html`,
		`docs\.github\.com`,
		`developer\.mozilla\.org`,
		`/documentation`,
		`/api/documentation`,
		`/docs/reference`,
		`charset=UTF-8`,
		`charset=utf-8`,
	},
	"messagebird_api_key": {
		`pickers`,
		`Pickers`,
		`Utility`,
		`Class`,
		`getPickersInput`,
		`function`,
		`return`,
		`getPickersOutlined`,
		`Outlined`,
		`getPickersFilled`,
		`_default`,
		`"function"`,
		`import`,
		`export`,
		`require`,
		`unstable`,
		`Unstable_`,
		`section`,
		`Section`,
		`InputBase`,
		`Classes`,
	},
	"cloudflare_api_token": {
		`eyJvcmlnaW4i`,
		`iidW7srW31oQ`,
		`origin`,
		`NNNNLNNNNN`,
		`NLNNN1LNNNNN`,
		`origin-trial`,
		`recaptcha`,
		`N1{10}N{5,}L{10,}`,
		`N+L+N+L+N+`,
		`n{5,}r{5,}m{5,}`,
		`m{5,}N+m{5,}r{5,}`,
		`b{5,}s{1,}b{5,}`,
		`eyJ(?:vcmlnaW4|ZlYXR1cmU|leHBpcnk|pcm1h)`,
	},
	"azure_sq_auth_key": {
		`eyJvcmlnaW4i`,
		`recaptcha`,
		`origin-trial`,
		`bbbbbbbbb`,
		`nnnnnn`,
		`mmmmmmm`,
		`NLNNN1LNNNNN`,
		`N1111111111N`,
	},
	"gcp_credentials": {
		`staticmethod`,
		`super`,
		`tuple`,
		`vars`,
		`zip`,
		`__import__`,
	},
	"fastspring_api_key": {
		`PROCESSING_INSTRUCTION_NODE`,
		`COMMENT_NODE`,
		`DOCUMENT_NODE`,
	},
	"bearer_token": {
		`children:"Bearer Token"`,
		`autoComplete="bearer-token"`,
		`placeholder="Bearer Token"`,
		`label="Bearer Token"`,
		`name="bearer"`,
		`class="bearer"`,
		`id="bearer"`,
	},
	"dropbox_long_token": {
		// Sequências repetitivas e padrões encontrados em códigos minificados
		`^[01]+$`,
		`^[0-9]{2}(?:\1)+$`,
		`^[0-9]{3}(?:\1)+$`,
		// Padrões de timezones e dados geográficos
		`^01[0-9]*2[0-9]*$`,
		`^012[0-9]+$`,
		// Códigos minificados comuns
		`[A-Z]{1,2}[0-9]{1,3}[A-Z]{1,2}`,
	},
	"coinbase_versioned_key": {
		// Padrões encontrados em JavaScript minificado
		`[A-Z]{1,2}[0-9]{1,2}[A-Z]{1,2}`,
		`[a-zA-Z]{1,2}[0-9]{1,2}[a-zA-Z]{1,2}`,
		// Variáveis curtas típicas de código minificado
		`[a-zA-Z][0-9][a-zA-Z][0-9]`,
		// Strings minificadas com códigos
		`[a-z]{1,3}[A-Z]{1,2}[0-9]{1,2}`,
		// Sequências de letras/números aleatórios em arquivos JS
		`[a-zA-Z0-9]{5,10}[a-zA-Z]{3,5}`,
	},
	"new_relic_license_key": {
		// Sequências de números repetitivos (comuns em JavaScript minificado)
		`[0-9]{1}(?:\1+){10,}`,
		`(?:[0-9]{2})\1{5,}`,
		`^[0-9]+$`,
		// Padrões específicos de timezone encontrados nos falsos positivos
		`^01[0-9]*$`,
		`^76[0-9]*$`,
		// Nomes e referências geográficas
		`Africa/`, `America/`, `Europe/`, `Asia/`, `Pacific/`,
		// Abreviações de timezone
		`GMT`, `UTC`, `EST`, `CST`, `MST`, `PST`, `CET`, `MSD`,
	},
	"basic_auth": {
		// Excluir referências ao Unicode e documentação
		`[Bb]asic [Mm]ultilingual`,
		`[Bb]asic [Ll]atin`,
		`[Bb]asic [Pp]lane`,
		`[Bb]asic [Ss]upport`,
		`[Bb]asic [Bb]lock`,
		`[Bb]asic [Ff]ormat`,
		// Excluir referências a documentação e exemplos
		`[Bb]asic [Tt]ype`,
		`[Bb]asic [Aa]uthentication`,
		`[Bb]asic [Ee]xample`,
	},
	"basic_auth_detailed": {
		// Mesmas exclusões do basic_auth
		`[Bb]asic [Mm]ultilingual`,
		`[Bb]asic [Ll]atin`,
		`[Bb]asic [Pp]lane`,
		`[Bb]asic [Ss]upport`,
		`[Bb]asic [Bb]lock`,
		`[Bb]asic [Ff]ormat`,
		`[Bb]asic [Tt]ype`,
		`[Bb]asic [Aa]uthentication`,
		`[Bb]asic [Ee]xample`,
	},
	"google_oauth_refresh": {
		// Excluir padrões de base64 comuns em código
		`1/[A-Za-z0-9]{10,}`,
		`[a-zA-Z0-9+/]{43,}`,
		`(?:app|cdn)\.js`,
		`\.min\.js`,
		`cdn\.`,
		`app\.`,
		`[a-z][A-Z][0-9][a-z]`,
		`[0-9][a-z][A-Z][0-9]`,
		`(?:[0-9]+[a-zA-Z]+){3,}`,
	},
	"oauth_token": {
		// Excluir padrões de código, não tokens verdadeiros
		`YO':`,
		`O'#`,
		`O':`,
		`O'A`,
		`QVO`,
		`QUO`,
		`app\.js`,
		`cdn\.`,
		`\.min\.js`,
		`1G1`,
		`[a-z][A-Z][0-9][a-z]`,
		`[0-9][a-z][A-Z][0-9]`,
		`[^a-zA-Z0-9_\-.]`, // Caracteres inválidos para tokens OAuth reais
	},
	"google_measurement_id": {
		// Excluir IDs falsos em código minificado
		`G-\d{1,2}[A-Z]{1,2}\d{1,2}[A-Z]{1,2}\d{1,2}`,
		`G-\d{1,2}[A-Z]{1,2}\d{1,2}[A-Z]{1,2}`,
		`app\.js`,
		`cdn\.`,
		`\.min\.js`,
		`\.js\?`,
		`vendor\.js`,
		`[a-zA-Z][0-9][A-Z][0-9]`,
		`[0-9][A-Z][0-9][A-Z]`,
	},
}
