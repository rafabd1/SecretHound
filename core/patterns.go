package core

// RegexPatterns contains all regex patterns for detecting secrets
var RegexPatterns = map[string]string{
	// API Keys
	"aws_key":               `AKIA[0-9A-Z]{16}`,
	"aws_secret":            `(?i)aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?['\"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]`,
	"google_api":            `AIza[0-9A-Za-z\-_]{35}`,
	"google_oauth":          `ya29\.[0-9A-Za-z\-_]+`,
	"google_cloud_platform": `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"google_captcha":        `6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`,
	"google_oauth_refresh":  `1/[0-9A-Za-z\-_]{43}|1/[0-9A-Za-z\-_]{64}`,
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
	"coinbase_versioned_key": `[0-9a-zA-Z]{64}`,
	"chargify_api_key":       `chrgfy-[a-zA-Z0-9]{43}`,
	"fastspring_api_key":     `[a-zA-Z0-9]{10}_[a-zA-Z0-9]{10}`,

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
	"azure_sq_auth_key":       `[a-zA-Z0-9_-]{64}`,
	"azure_sql_conn_string":   `(?i)Server=tcp:[^,]+,1433;Initial Catalog=[^;]+;Persist Security Info=False;User ID=[^;]+;Password=[^;]+;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;`,
	"cloudinary_url":          `cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9_-]{30,35}@[a-zA-Z0-9_-]+`,
	"cloudinary_basic_auth":   `(?i)cloudinary[._-]?(?:api|url)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([0-9a-zA-Z:@]+)["']`,
	"digitalocean_access_key": `(?i)digitalocean[._-]?(?:api|access)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9]{64})["']`,
	"digitalocean_pat":        `dop_v1_[a-f0-9]{64}`,
	"dropbox_api_key":         `(?i)dropbox[._-]?(?:api|access)?[._-]?(?:key|token|secret)(?:[._-]?id)?[\s]*[=:][\s]*["']([a-zA-Z0-9_-]{15,150})["']`,
	"dropbox_short_token":     `sl\.[a-zA-Z0-9_-]{130,145}`,
	"dropbox_long_token":      `[a-zA-Z0-9_-]{130,150}`,
	"github_pat":              `ghp_[a-zA-Z0-9_]{36}`,
	"github_pat_v2":           `github_pat_[a-zA-Z0-9_]{82}`,
	"gcp_api_key":             `AIza[a-zA-Z0-9_-]{35}`,
	"gcp_credentials":         `(?:"|')(?:type|project_id|private_key_id|private_key|client_email|client_id|auth_uri|token_uri|auth_provider_x509_cert_url|client_x509_cert_url)(?:"|')`,
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
	"twilio_account_sid":  `AC[a-zA-Z0-9_\-]{32}`,
	"twilio_app_sid":      `AP[a-zA-Z0-9_\-]{32}`,
	"twilio_auth_token":   `(?i)twilio[._-]?(?:api|app|account)?[._-]?(?:key|token|secret|sid|id|auth_token)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32})["']`,
	"nexmo_api_key":       `(?i)nexmo[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{8})["']`,
	"nexmo_api_secret":    `(?i)nexmo[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{16})["']`,
	"vonage_api_key":      `(?i)vonage[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{8})["']`,
	"messagebird_api_key": `(?:(?:production|live)_)?[a-zA-Z0-9]{25}`,
	"infobip_api_key":     `(?i)infobip[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32,50})["']`,
	"sinch_api_key":       `(?i)sinch[._-]?(?:api)?[._-]?(?:key|token|secret|id)[\s]*[=:][\s]*["']([a-zA-Z0-9]{32,64})["']`,

	// Authentication Credentials
	"basic_auth":          `(?i)(?:basic\s*)(?:[a-zA-Z0-9\+\/=]{5,100})`,
	"basic_auth_detailed": `(?i)(?:basic\s*)(?:[a-zA-Z0-9\+\/=]{5,100})`,
	"bearer_token":        `(?i)(?:bearer\s*)(?:[a-zA-Z0-9_\-\.=:_\+\/]{5,100})`,
	"jwt_token":           `(?i)(?:ey[a-zA-Z0-9]{2,4}\.ey[a-zA-Z0-9\/\\_-]{10,}\.(?:[a-zA-Z0-9\/\\_-]*))`,
	"oauth_token":         `(?i)('|")?[a-z0-9_-]+('|")?(?:\s*):(?:\s*)('|")?[a-z0-9!]{30,}('|")?`,
	"generic_password":    `(?i)(password|passwd|pwd|secret)[\s]*[=:]+[\s]*['"][^'"]{4,30}['"]`,
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
	"google_measurement_id":        `G-[A-Z0-9]{10}`,
	"segment_api_key":              `(?i)(?:segment)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{20,72}['"\s]*[\n,;]`,
	"amplitude_api_key":            `(?i)(?:amplitude)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,72}['"\s]*[\n,;]`,
	"mixpanel_project_token":       `(?i)(?:mixpanel)(?:_|-|\.)(?:api|project)?(?:_|-|\.)?(?:key|token|id)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"matomo_auth_token":            `(?i)(?:matomo)(?:_|-|\.)(?:auth)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"fullstory_api_key":            `(?i)(?:fullstory)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,
	"piwik_auth_token":             `(?i)(?:piwik)(?:_|-|\.)(?:auth)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{5,72}['"\s]*[\n,;]`,

	// Content Delivery Networks
	"cloudflare_api_key":        `(?i)(?:cloudflare)(?:_|-|\.)(?:api)?(?:_|-|\.)?(?:key|token|secret)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,50}['"\s]*[\n,;]`,
	"cloudflare_api_token":      `(?i)(?:[a-z0-9]{40,100})`,
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
	"new_relic_license_key":   `(?i)[a-f0-9]{40}`,
	"new_relic_insights_key":  `(?i)(?:insights)?(?:_|-|\.)?(?:insert)?(?:_|-|\.)(?:key|api_key)['"\s=:]+(?-i)[a-zA-Z0-9_-]{16,40}['"\s]*[\n,;]`,
	"npm_access_token":        `(?i)(?:npm)(?:_|-|\.)(?:access_token|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{40,100}['"\s]*[\n,;]`,
	"sentry_access_token":     `(?i)(?:sentry)(?:_|-|\.)(?:access_token|token|secret|password|credential)['"\s=:]+(?-i)[a-zA-Z0-9_-]{32,100}['"\s]*[\n,;]`,
	"sentry_dsn":              `https?:\/\/[a-zA-Z0-9]+@[a-zA-Z0-9]+\.ingest\.sentry\.io\/[0-9]+`,

	// Generic Secrets
	"generic_api_key":     `(?i)(?:api[_-]?(?:key)|token|secret)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]`,
	"generic_secret":      `(?i)(?:secret|private[_-]?key|password)[\s]*[=:]+[\s]*['"][a-zA-Z0-9_\-+=,./:]{8,100}['"]`,
	"high_entropy_string": `(?i)(?:[^a-z0-9_.-]|^)([a-zA-Z0-9_\-]{32,100})(?:[^a-z0-9_.-]|$)`,
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
	
	// jQuery and JavaScript specific patterns
	`jQuery`,
	`\$\(`,
	`\.ready\(`,
	`\.click\(`,
	`\.on\(`,
	
	// Common JavaScript patterns
	`function\(t,e`,
	`function\(e,t`,
	`return[a-z]&&`,
	`\?[a-z]\.`,
	`:[a-z]\.`,
}

// SpecificExclusions is a map of specific exclusions for each regex pattern
var SpecificExclusions = map[string][]string{
	"amazon_aws_url": {
		`selectors`,
		`css3-selectors`,
		`REC-css3-selectors`,
		`w3.org/TR`,
	},
	"amazon_aws_url2": {
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
	"twilio_account_sid": {
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
	"twilio_app_sid": {
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
	"Heroku API KEY": {
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
		// Arquivo e recursos
		`[a-f0-9]{32}\.png`,
		`[a-f0-9]{32}\.jpe?g`,
		`[a-f0-9]{32}\.gif`,
		`[a-f0-9]{32}\.svg`,
		`[a-f0-9]{32}\.webp`,
		`[a-f0-9]{32,40}\.min\.(js|css)`,
		// Padrões já cobertos por outros detectores específicos
		`pk_live_[0-9a-zA-Z]{24}`,            // stripe_publishable_key
		`sk_live_[0-9a-zA-Z]{24}`,            // stripe_api_key
		`sk_test_[0-9a-zA-Z]{24}`,            // stripe_test_key
		`pk_test_[0-9a-zA-Z]{24}`,            // stripe test key
		`AIza[0-9A-Za-z\-_]{35}`,             // google_api
		`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}`,  // JWT tokens
		`GOCSPX-[a-zA-Z0-9_-]{20,30}`,        // Google OAuth client secret
		`api_key_[a-zA-Z0-9]{20,40}`,         // Named API keys
		`admin_api_[a-zA-Z0-9]{20,40}`,       // Admin API keys
		`tr_sec_[a-zA-Z0-9]{20,40}`,          // Transaction secrets
		`[a-zA-Z]{10,20}(Token|Secret|Key)[a-zA-Z0-9]{5,30}`,  // Common naming patterns
		`npm_[a-zA-Z0-9_]{10,60}`,            // NPM tokens
		`node_[a-zA-Z0-9_]{10,60}`,           // Node related tokens
		`react_[a-zA-Z0-9_]{10,60}`,          // React related tokens
		`angular_[a-zA-Z0-9_]{10,60}`,        // Angular related tokens
		`vue_[a-zA-Z0-9_]{10,60}`,            // Vue related tokens
		`github_pat_[a-zA-Z0-9_]{60,90}`,     // GitHub personal access tokens
		`ghp_[a-zA-Z0-9]{36}`,                // GitHub personal access tokens
		`gho_[a-zA-Z0-9]{36}`,                // GitHub OAuth tokens
	},
}
