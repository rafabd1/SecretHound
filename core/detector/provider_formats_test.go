package detector

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/secret"
)

func TestCurrentGitHubTokenFormats(t *testing.T) {
	detector := categoryDetector(t, "code")
	oauth := "gho_" + providerFixture(36)
	installation := "ghs_" + providerFixture(220) + "." + providerFixture(180) + "." + providerFixture(110)
	content := "oauth=" + oauth + "\ninstallation=" + installation

	findings, err := detector.DetectSecrets(content, "file://production/github.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "github_personal_token", oauth)
	assertProviderFinding(t, findings, "github_token", installation)
	for _, finding := range findings {
		if finding.Value == installation && finding.Type == "github_personal_token" {
			t.Fatalf("installation token collided with personal-token rule: %+v", findings)
		}
	}
}

func TestGitLabTokensAreNotTruncatedAtRoutableSuffix(t *testing.T) {
	codeDetector := categoryDetector(t, "code")
	classic := "glpat-" + providerFixture(20)
	routable := "glpat-" + providerFixture(30) + ".a1b2c3d4e"
	versioned := "glpat-" + providerFixture(30) + ".v1.a1b2c3d4e"
	findings, err := codeDetector.DetectSecrets(
		strings.Join([]string{classic, routable, versioned}, "\n"),
		"file://production/gitlab.env",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{classic, routable, versioned} {
		assertProviderFinding(t, findings, "gitlab_personal_token", value)
	}

	runnerDetector := categoryDetector(t, "ci")
	runner := "glrt-" + providerFixture(30) + ".v1.a1b2c3d4e"
	runnerFindings, err := runnerDetector.DetectSecrets(runner, "file://production/runner.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, runnerFindings, "gitlab_runner_token", runner)

	malformed := classic + ".truncated"
	malformedFindings, err := codeDetector.DetectSecrets(malformed, "file://production/gitlab.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range malformedFindings {
		if finding.Type == "gitlab_personal_token" {
			t.Fatalf("GitLab rule emitted a partial token: %+v", malformedFindings)
		}
	}

	punctuatedFindings, err := codeDetector.DetectSecrets(classic+".", "file://production/gitlab.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, punctuatedFindings, "gitlab_personal_token", classic)

	runnerClassic := "glrt-" + providerFixture(20)
	runnerPunctuated, err := runnerDetector.DetectSecrets(runnerClassic+".", "file://production/runner.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, runnerPunctuated, "gitlab_runner_token", runnerClassic)
}

func TestCurrentAdditionalGitLabTokenFamilies(t *testing.T) {
	ciDetector := categoryDetector(t, "ci")
	ciValues := map[string]string{
		"gitlab_pipeline_trigger_token":    "glptt-" + providerFixture(40),
		"gitlab_runner_registration_token": "GR1348941" + providerFixture(20),
		"gitlab_kubernetes_agent_token":    "glagent-" + providerFixture(50),
		"gitlab_deploy_token":              "gldt-" + providerFixture(20),
		"gitlab_ci_build_token":            "glcbt-a12_" + providerFixture(20),
	}
	var ciContent []string
	for _, value := range ciValues {
		ciContent = append(ciContent, value)
	}
	ciFindings, err := ciDetector.DetectSecrets(strings.Join(ciContent, "\n"), "file://production/gitlab-ci.env")
	if err != nil {
		t.Fatal(err)
	}
	for patternName, value := range ciValues {
		assertProviderFinding(t, ciFindings, patternName, value)
	}

	authDetector := categoryDetector(t, "auth")
	authValues := map[string]string{
		"gitlab_oauth_app_secret":     "gloas-" + providerFixture(64),
		"gitlab_feed_token":           "glft-" + providerFixture(20),
		"gitlab_incoming_email_token": "glimt-" + providerFixture(25),
		"gitlab_scim_oauth_token":     "glsoat-" + providerFixture(20),
		"gitlab_legacy_feed_token":    providerFixture(20),
	}
	var authContent []string
	for patternName, value := range authValues {
		if patternName == "gitlab_legacy_feed_token" {
			authContent = append(authContent, `feed_token="`+value+`"`)
		} else {
			authContent = append(authContent, value)
		}
	}
	authContent = append(authContent, "gloas-"+providerFixture(65), "glft-"+providerFixture(21))
	authFindings, err := authDetector.DetectSecrets(strings.Join(authContent, "\n"), "file://production/gitlab-auth.env")
	if err != nil {
		t.Fatal(err)
	}
	for patternName, value := range authValues {
		assertProviderFinding(t, authFindings, patternName, value)
	}
	counts := make(map[string]int)
	for _, finding := range authFindings {
		expected, tracked := authValues[finding.Type]
		if !tracked {
			continue
		}
		counts[finding.Type]++
		if finding.Value != expected {
			t.Fatalf("GitLab rule emitted a partial token: %+v", finding)
		}
	}
	for patternName := range authValues {
		if counts[patternName] != 1 {
			t.Fatalf("expected one %s finding, got %d: %+v", patternName, counts[patternName], authFindings)
		}
	}
}

func TestCurrentGitLabFamiliesReachRemoteConfidenceThreshold(t *testing.T) {
	ciDetector := categoryDetector(t, "ci")
	ciDetector.config.LocalFileMode = false
	ciValues := map[string]string{
		"gitlab_pipeline_trigger_token":    "glptt-" + underscoredProviderFixture(40),
		"gitlab_runner_registration_token": "GR1348941" + underscoredProviderFixture(20),
		"gitlab_kubernetes_agent_token":    "glagent-" + underscoredProviderFixture(50),
		"gitlab_deploy_token":              "gldt-" + underscoredProviderFixture(20),
		"gitlab_ci_build_token":            "glcbt-a12_" + underscoredProviderFixture(20),
	}
	var ciContent []string
	for _, value := range ciValues {
		ciContent = append(ciContent, value)
	}
	ciFindings, err := ciDetector.DetectSecrets(strings.Join(ciContent, "\n"), "https://gitlab.example/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for patternName, value := range ciValues {
		assertProviderFinding(t, ciFindings, patternName, value)
	}

	authDetector := categoryDetector(t, "auth")
	authDetector.config.LocalFileMode = false
	authValues := map[string]string{
		"gitlab_oauth_app_secret":     "gloas-" + underscoredProviderFixture(64),
		"gitlab_feed_token":           "glft-" + underscoredProviderFixture(20),
		"gitlab_incoming_email_token": "glimt-" + underscoredProviderFixture(25),
		"gitlab_scim_oauth_token":     "glsoat-" + underscoredProviderFixture(20),
	}
	var authContent []string
	for _, value := range authValues {
		authContent = append(authContent, value)
	}
	authFindings, err := authDetector.DetectSecrets(strings.Join(authContent, "\n"), "https://gitlab.example/assets/auth.js")
	if err != nil {
		t.Fatal(err)
	}
	for patternName, value := range authValues {
		assertProviderFinding(t, authFindings, patternName, value)
	}
}

func TestCurrentSlackTokenFamilies(t *testing.T) {
	detector := categoryDetector(t, "code")
	standard := "xoxb-" + providerFixture(48)
	rotating := "xoxe.xoxb-" + providerFixture(48)
	refresh := "xoxe-" + providerFixture(48)
	findings, err := detector.DetectSecrets(
		strings.Join([]string{standard, rotating, refresh, "team_id=T0123456789", "channel_id=C0123456789"}, "\n"),
		"file://production/slack.env",
	)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "slack_token", standard)
	assertProviderFinding(t, findings, "slack_rotating_token", rotating)
	assertProviderFinding(t, findings, "slack_refresh_token", refresh)
	for _, finding := range findings {
		if finding.Type == "slack_token" && finding.Value != standard {
			t.Fatalf("standard Slack rule captured part of another token: %+v", finding)
		}
	}
}

func TestCurrentCloudflareTokenFormatsAndPublicIDNegative(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	var values []string
	for _, prefix := range []string{"cfk_", "cfut_", "cfat_"} {
		values = append(values, prefix+providerFixture(40)+"a1b2c3d4")
	}
	legacy := providerFixture(40)
	content := strings.Join(append(values,
		`CLOUDFLARE_API_TOKEN="`+legacy+`"`,
		`CLOUDFLARE_ACCOUNT_ID="0123456789abcdef0123456789abcdef"`,
		`CLOUDFLARE_ZONE_ID="fedcba9876543210fedcba9876543210"`,
	), "\n")

	findings, err := detector.DetectSecrets(content, "file://production/cloudflare.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		assertProviderFinding(t, findings, "cloudflare_api_token", value)
	}
	assertProviderFinding(t, findings, "cloudflare_legacy_api_token", legacy)
	for _, finding := range findings {
		if strings.Contains(finding.Value, "0123456789abcdef0123456789abcdef") ||
			strings.Contains(finding.Value, "fedcba9876543210fedcba9876543210") {
			t.Fatalf("Cloudflare public identifier was emitted: %+v", finding)
		}
	}
}

func TestCurrentSentryTokenFormatsAndPublicDSNNegative(t *testing.T) {
	detector := categoryDetector(t, "observability")
	hex := strings.Repeat("0123456789abcdef", 4)
	typed := "sntryu_" + hex
	organization := "sntrys_eyJ" + "A7kQ/src" + providerFixture(32) + "_" + providerFixture(43)
	legacy := strings.Repeat("fedcba9876543210", 4)
	content := strings.Join([]string{
		typed,
		organization,
		`SENTRY_AUTH_TOKEN="` + legacy + `"`,
		`SENTRY_DSN="https://public@example.ingest.sentry.io/123"`,
	}, "\n")

	findings, err := detector.DetectSecrets(content, "file://production/sentry.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "sentry_auth_token", typed)
	assertProviderFinding(t, findings, "sentry_org_auth_token", organization)
	assertProviderFinding(t, findings, "sentry_legacy_auth_token", legacy)
	for _, finding := range findings {
		if strings.Contains(finding.Value, "example.ingest.sentry.io") {
			t.Fatalf("public Sentry DSN was emitted as an auth token: %+v", finding)
		}
	}
}

func TestCurrentPostmanKeyFormat(t *testing.T) {
	detector := categoryDetector(t, "code")
	value := "PMAK-0123456789abcdef01234567-" + providerFixture(34)
	oldMalformed := "PMAK-" + providerFixture(59)
	content := strings.Join([]string{value, oldMalformed, "PMAK-your-key-here"}, "\n")

	findings, err := detector.DetectSecrets(content, "file://production/postman.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "postman_api_key", value)
	for _, finding := range findings {
		if finding.Type == "postman_api_key" && finding.Value != value {
			t.Fatalf("invalid Postman value was emitted: %+v", finding)
		}
	}
}

func TestBoundedCatalogPatternsPreserveValuesAndRejectExtensions(t *testing.T) {
	tests := []struct {
		name             string
		category         string
		label            string
		value            string
		extension        string
		extensionIsValid bool
		leftExtension    string
	}{
		{
			name:          "bearer_token",
			category:      "auth",
			label:         "AUTHORIZATION",
			value:         "Bearer " + providerFixture(500),
			extension:     "A",
			leftExtension: "x",
		},
		{
			name:          "braintree_token",
			category:      "payment",
			label:         "BRAINTREE_ACCESS_TOKEN",
			value:         "access_token$production$a1b2c3d4e5f60718$" + strings.Repeat("a1b2c3d4", 4),
			extension:     "a",
			leftExtension: "x",
		},
		{
			name:          "mailchimp_api_key",
			category:      "cloud",
			label:         "MAILCHIMP_API_KEY",
			value:         strings.Repeat("a1b2c3d4", 4) + "-us12",
			extension:     "3",
			leftExtension: "x",
		},
		{
			name:     "slack_webhook",
			category: "code",
			label:    "SLACK_WEBHOOK",
			value: "https://hooks.slack.com/services/T" + providerFixture(8) +
				"/B" + providerFixture(8) + "/" + providerFixture(32),
			extension:     "A",
			leftExtension: "x",
		},
		{
			name:             "discord_webhook",
			category:         "code",
			label:            "DISCORD_WEBHOOK",
			value:            "https://discord.com/api/webhooks/1234567890123456789/" + providerFixture(68),
			extension:        "A",
			extensionIsValid: true,
			leftExtension:    "x",
		},
		{
			name:      "telegram_bot_token",
			category:  "communication",
			label:     "TELEGRAM_BOT_TOKEN",
			value:     "12345678:" + providerFixture(35),
			extension: "-tail",
		},
		{
			name:      "mapbox_secret_token",
			category:  "cloud",
			label:     "MAPBOX_SECRET_TOKEN",
			value:     "sk." + providerFixture(240),
			extension: ".tail",
		},
		{
			name:      "huggingface_api_token",
			category:  "llm",
			label:     "HUGGINGFACE_TOKEN",
			value:     "hf_" + providerFixture(34),
			extension: "_tail",
		},
		{
			name:      "llm_anthropic_api_key",
			category:  "llm",
			label:     "ANTHROPIC_API_KEY",
			value:     "sk-ant-api03-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_groq_api_key",
			category:  "llm",
			label:     "GROQ_API_KEY",
			value:     "gsk_" + providerFixture(200),
			extension: "_tail",
		},
		{
			name:      "llm_xai_grok_api_key",
			category:  "llm",
			label:     "XAI_API_KEY",
			value:     "xai-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_kimi_moonshot_api_key",
			category:  "llm",
			label:     "KIMI_API_KEY",
			value:     "sk-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_qwen_dashscope_api_key",
			category:  "llm",
			label:     "DASHSCOPE_API_KEY",
			value:     "sk-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_zhipu_glm_api_key",
			category:  "llm",
			label:     "ZHIPU_API_KEY",
			value:     providerFixture(32) + "." + providerFixture(16),
			extension: ".tail",
		},
		{
			name:      "llm_doubao_ark_api_key",
			category:  "llm",
			label:     "DOUBAO_API_KEY",
			value:     "ark-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_openrouter_api_key",
			category:  "llm",
			label:     "OPENROUTER_API_KEY",
			value:     "sk-or-v1-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_perplexity_api_key",
			category:  "llm",
			label:     "PERPLEXITY_API_KEY",
			value:     "pplx-" + providerFixture(200),
			extension: "-tail",
		},
		{
			name:      "llm_replicate_api_token",
			category:  "llm",
			label:     "REPLICATE_API_TOKEN",
			value:     "r8_" + providerFixture(200),
			extension: "_tail",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := categoryDetector(t, test.category)
			content := test.label + `="` + test.value + `"`
			findings, err := detector.DetectSecrets(content, "file://production/credentials.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.name, test.value)

			if test.extension != "" {
				extendedValue := test.value + test.extension
				extended := test.label + `="` + extendedValue + `"`
				extendedFindings, err := detector.DetectSecrets(extended, "file://production/credentials.env")
				if err != nil {
					t.Fatal(err)
				}
				if test.extensionIsValid {
					assertProviderFinding(t, extendedFindings, test.name, extendedValue)
				} else {
					for _, finding := range extendedFindings {
						if finding.Type == test.name {
							t.Fatalf("pattern emitted a truncated value from an extended token: %+v", finding)
						}
					}
				}
			}

			if test.leftExtension != "" {
				extended := test.label + `="` + test.leftExtension + test.value + `"`
				extendedFindings, err := detector.DetectSecrets(extended, "file://production/credentials.env")
				if err != nil {
					t.Fatal(err)
				}
				for _, finding := range extendedFindings {
					if finding.Type == test.name {
						t.Fatalf("pattern emitted a suffix from a left-extended token: %+v", finding)
					}
				}
			}
		})
	}
}

func assertProviderFinding(t *testing.T, findings []secret.Secret, patternName, value string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Type == patternName && finding.Value == value {
			return
		}
	}
	t.Fatalf("missing %s finding for %q: %+v", patternName, value, findings)
}

func providerFixture(length int) string {
	const seed = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	return strings.Repeat(seed, length/len(seed)+1)[:length]
}

func underscoredProviderFixture(length int) string {
	const seed = "A7_kQ9_mX2_vR5_tY8_uP3_nD6_cB1_hF4_jW0_zE2_"
	return strings.Repeat(seed, length/len(seed)+1)[:length]
}
