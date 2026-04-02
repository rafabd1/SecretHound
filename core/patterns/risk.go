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
	case "private_key_content",
		"private_key_var",
		"web3_private_key",
		"aws_secret_key",
		"github_personal_token",
		"github_token",
		"github_fine_grained_token",
		"gitlab_personal_token",
		"gitlab_runner_token",
		"docker_hub_token",
		"npm_access_token",
		"slack_token",
		"sentry_auth_token",
		"shopify_private_app_token",
		"shopify_custom_app_token",
		"stripe_secret_key",
		"stripe_test_secret_key",
		"supabase_service_role_key":
		return RiskHigh
	}

	// Typically public/low-impact identifiers.
	switch patternType {
	case "google_recaptcha_key",
		"ethereum_address",
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
	}

	category := ""
	if pm != nil {
		if cfg, ok := pm.GetPatternConfig(patternType); ok {
			category = strings.ToLower(strings.TrimSpace(cfg.Category))
		}
	}

	switch category {
	case "pii", "web3":
		return RiskInformative
	case "gcp", "generic":
		return RiskLow
	case "auth", "aws", "azure", "code", "config", "crypto", "db", "llm", "payment", "ci", "bash":
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
