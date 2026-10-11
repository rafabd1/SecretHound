package patterns

import "strings"

type FindingRisk string

const (
	RiskInformative FindingRisk = "informative"
	RiskLow         FindingRisk = "low"
	RiskMedium      FindingRisk = "medium"
	RiskHigh        FindingRisk = "high"
)

func ResolveFindingRisk(patternType string, pm *PatternManager) FindingRisk {
	patternType = strings.ToLower(strings.TrimSpace(patternType))
	if patternType == "" {
		return RiskMedium
	}

	// High-confidence sensitive types.
	switch patternType {
	case "api_key_assignment",
		"cloudflare_api_token",
		"cloudflare_legacy_api_token",
		"datadog_api_key",
		"digitalocean_access_token",
		"digitalocean_oauth_token",
		"digitalocean_refresh_token",
		"generic_password",
		"gitlab_ci_build_token",
		"gitlab_deploy_token",
		"gitlab_feed_token",
		"gitlab_incoming_email_token",
		"gitlab_kubernetes_agent_token",
		"gitlab_legacy_feed_token",
		"gitlab_oauth_app_secret",
		"gitlab_pipeline_trigger_token",
		"gitlab_runner_registration_token",
		"gitlab_runner_token",
		"gitlab_scim_oauth_token",
		"mailgun_api_key",
		"mapbox_secret_token",
		"netlify_access_token",
		"postman_api_key",
		"private_key_content",
		"private_key_var",
		"web3_private_key",
		"aws_secret_key",
		"github_personal_token",
		"github_token",
		"github_fine_grained_token",
		"gitlab_personal_token",
		"docker_hub_token",
		"npm_access_token",
		"sendgrid_api_key",
		"sendinblue_api_key",
		"shopify_access_token",
		"shopify_private_app_token",
		"shopify_custom_app_token",
		"shopify_shared_secret",
		"sentry_auth_token",
		"sentry_legacy_auth_token",
		"sentry_org_auth_token",
		"slack_refresh_token",
		"slack_rotating_token",
		"slack_token",
		"stripe_secret_key",
		"supabase_service_role_key",
		"google_recaptcha_key",
		"session_token":
		return RiskHigh
	}

	// Typically public/low-impact identifiers.
	switch patternType {
	case "ethereum_address",
		"aws_access_key",
		"public_key",
		"public_key_content",
		"stripe_test_publishable_key":
		return RiskInformative
	case "google_api_key",
		"google_cloud_platform",
		"stripe_publishable_key",
		"supabase_anon_key",
		"supabase_publishable_key":
		return RiskLow
	case "stripe_test_secret_key":
		return RiskMedium
	}

	category := ""
	if pm != nil {
		if cfg, ok := pm.GetPatternConfig(patternType); ok {
			category = strings.ToLower(strings.TrimSpace(cfg.Category))
		}
	}

	switch category {
	case "pii", "url":
		return RiskInformative
	case "gcp", "generic":
		return RiskLow
	case "auth", "aws", "azure", "code", "config", "crypto", "db", "llm", "payment", "ci", "bash", "web3":
		return RiskHigh
	case "cloud":
		return RiskMedium
	}

	// Name-based fallback for custom and external patterns.
	if strings.Contains(patternType, "private") ||
		strings.Contains(patternType, "secret") ||
		strings.Contains(patternType, "token") {
		if strings.Contains(patternType, "publishable") || strings.Contains(patternType, "public") {
			return RiskLow
		}
		return RiskHigh
	}

	if strings.Contains(patternType, "publishable") {
		return RiskLow
	}

	if strings.Contains(patternType, "public") ||
		strings.Contains(patternType, "email") ||
		strings.Contains(patternType, "phone") {
		return RiskInformative
	}

	return RiskMedium
}
