package patterns

import "testing"

func TestResolveFindingRiskDistinguishesSecretsFromPublicIdentifiers(t *testing.T) {
	manager := NewPatternManager()
	tests := []struct {
		name string
		want FindingRisk
	}{
		{name: "google_recaptcha_key", want: RiskHigh},
		{name: "session_token", want: RiskHigh},
		{name: "web3_provider_key", want: RiskHigh},
		{name: "cloudflare_api_token", want: RiskHigh},
		{name: "datadog_api_key", want: RiskHigh},
		{name: "digitalocean_access_token", want: RiskHigh},
		{name: "mailgun_api_key", want: RiskHigh},
		{name: "netlify_access_token", want: RiskHigh},
		{name: "sendgrid_api_key", want: RiskHigh},
		{name: "sendinblue_api_key", want: RiskHigh},
		{name: "shopify_access_token", want: RiskHigh},
		{name: "shopify_shared_secret", want: RiskHigh},
		{name: "mapbox_secret_token", want: RiskHigh},
		{name: "gitlab_pipeline_trigger_token", want: RiskHigh},
		{name: "sentry_org_auth_token", want: RiskHigh},
		{name: "slack_refresh_token", want: RiskHigh},
		{name: "stripe_test_secret_key", want: RiskMedium},
		{name: "aws_access_key", want: RiskInformative},
		{name: "ethereum_address", want: RiskInformative},
		{name: "stripe_publishable_key", want: RiskLow},
	}

	for _, test := range tests {
		if got := ResolveFindingRisk(test.name, manager); got != test.want {
			t.Errorf("ResolveFindingRisk(%q) = %q, want %q", test.name, got, test.want)
		}
	}
}
