package detector

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestProviderScopedShortTokenIsNotKilledByGenericEntropyGate(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	value := "A7kQ9mX2vR5tY8uP3nD6"
	findings, err := detector.DetectSecrets(
		`aeroworkflow_api_token = "`+value+`"`,
		"file://production/config.js",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "aeroworkflow_2" && finding.Value == value {
			return
		}
	}
	t.Fatalf("provider-scoped token was rejected: %+v", findings)
}

func TestLooseProviderPrefixAndCredentialLabelAreCaseInsensitive(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	value := "A7kQ9mX2vR5tY8uP3nD6"
	findings, err := detector.DetectSecrets(
		`AEROWORKFLOW_API_TOKEN = "`+value+`"`,
		"file://production/config.env",
	)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "aeroworkflow_2", value)
}

func TestSendinblueExactLengthTokenReachesDetector(t *testing.T) {
	manager := patterns.NewPatternManager()
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
	value := "xkeysib-" + strings.Repeat("Ab3dEf6hIj9kLm2nOp5qRs8t", 4)[:81]
	if len(value) != 89 {
		t.Fatalf("fixture length = %d", len(value))
	}
	findings, err := detector.DetectSecrets("BREVO_API_KEY="+value, "file://production.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "sendinblue_api_key" && finding.Value == value {
			return
		}
	}
	t.Fatalf("Sendinblue token was rejected: %+v", findings)
}

func TestFixedFormatTokensRejectLongerAlphabetContinuation(t *testing.T) {
	awsAccess := "AKIAA7KQ9MX2VR5TY8UP"
	awsSecret := providerFixture(40)
	google := "AIzaSyD7mQ9xV2nR5tY8uP3kL6cB1hF4jW0zE7Q"
	npm := "npm_" + providerFixture(36)
	squareAccess := "sq0atp-" + providerFixture(22)
	squareOAuth := "sq0csp-" + providerFixture(43)
	stripe := "sk_live_" + providerFixture(34)
	brevo := "xkeysib-" + providerFixture(80) + "-"
	hex64 := strings.Repeat("a1b2c3d4e5f6", 6)[:64]
	digitalOcean := "dop_v1_" + hex64
	docker := "dckr_pat_" + providerFixture(56)
	netlify := "nfp_" + providerFixture(36)
	mailgun := "key-" + providerFixture(32)
	sendgrid := "SG." + providerFixture(22) + "." + providerFixture(43)
	shopify := "shpat_" + hex64[:32]
	recaptcha := "6L" + providerFixture(58)
	web3 := providerFixture(128)

	tests := []struct {
		name       string
		category   string
		pattern    string
		value      string
		continuing string
		content    func(string) string
	}{
		{name: "aws access", category: "aws", pattern: "aws_access_key", value: awsAccess, continuing: "A", content: func(value string) string { return value }},
		{name: "aws secret", category: "aws", pattern: "aws_secret_key", value: awsSecret, continuing: "A", content: func(value string) string { return `AWS_SECRET_ACCESS_KEY="` + value + `"` }},
		{name: "google", category: "gcp", pattern: "google_api_key", value: google, continuing: "A", content: func(value string) string { return value }},
		{name: "npm", category: "code", pattern: "npm_access_token", value: npm, continuing: "A", content: func(value string) string { return value }},
		{name: "square access", category: "payment", pattern: "square_access_token", value: squareAccess, continuing: "_", content: func(value string) string { return value }},
		{name: "square oauth", category: "payment", pattern: "square_oauth_secret", value: squareOAuth, continuing: "_", content: func(value string) string { return value }},
		{name: "stripe", category: "payment", pattern: "stripe_secret_key", value: stripe, continuing: "A", content: func(value string) string { return value }},
		{name: "brevo", category: "communication", pattern: "sendinblue_api_key", value: brevo, continuing: "_", content: func(value string) string { return value }},
		{name: "digitalocean", category: "cloud", pattern: "digitalocean_access_token", value: digitalOcean, continuing: "a", content: func(value string) string { return value }},
		{name: "docker", category: "code", pattern: "docker_hub_token", value: docker, continuing: "_", content: func(value string) string { return value }},
		{name: "netlify", category: "cloud", pattern: "netlify_access_token", value: netlify, continuing: "_", content: func(value string) string { return value }},
		{name: "mailgun", category: "communication", pattern: "mailgun_api_key", value: mailgun, continuing: "A", content: func(value string) string { return value }},
		{name: "sendgrid", category: "communication", pattern: "sendgrid_api_key", value: sendgrid, continuing: "_", content: func(value string) string { return value }},
		{name: "shopify", category: "cloud", pattern: "shopify_access_token", value: shopify, continuing: "a", content: func(value string) string { return value }},
		{name: "recaptcha", category: "auth", pattern: "google_recaptcha_key", value: recaptcha, continuing: "A", content: func(value string) string { return "RECAPTCHA_SECRET=" + value }},
		{name: "web3", category: "web3", pattern: "web3_provider_key", value: web3, continuing: "A", content: func(value string) string { return "infura_api_secret=" + value }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := categoryDetector(t, test.category)
			findings, err := detector.DetectSecrets(test.content(test.value), "file://production/provider.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.pattern, test.value)

			longerFindings, err := detector.DetectSecrets(test.content(test.value+test.continuing), "file://production/provider.env")
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range longerFindings {
				if finding.Type == test.pattern {
					t.Fatalf("%s captured a truncated prefix from %q: %+v", test.pattern, test.value+test.continuing, longerFindings)
				}
			}
		})
	}
}

func TestHexCredentialFormatsRejectIdentifierContinuations(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	hex32 := hex64[:32]
	tests := []struct {
		name     string
		category string
		pattern  string
		value    string
		content  func(string) string
	}{
		{name: "digitalocean access", category: "cloud", pattern: "digitalocean_access_token", value: "dop_v1_" + hex64, content: func(value string) string { return value }},
		{name: "digitalocean oauth", category: "cloud", pattern: "digitalocean_oauth_token", value: "doo_v1_" + hex64, content: func(value string) string { return value }},
		{name: "digitalocean refresh", category: "cloud", pattern: "digitalocean_refresh_token", value: "dor_v1_" + hex64, content: func(value string) string { return value }},
		{name: "shopify access", category: "cloud", pattern: "shopify_access_token", value: "shpat_" + hex32, content: func(value string) string { return value }},
		{name: "shopify custom", category: "cloud", pattern: "shopify_custom_app_token", value: "shpca_" + hex32, content: func(value string) string { return value }},
		{name: "shopify private", category: "cloud", pattern: "shopify_private_app_token", value: "shppa_" + hex32, content: func(value string) string { return value }},
		{name: "shopify shared", category: "cloud", pattern: "shopify_shared_secret", value: "shpss_" + hex32, content: func(value string) string { return value }},
		{name: "sentry legacy", category: "observability", pattern: "sentry_legacy_auth_token", value: hex64, content: func(value string) string { return "sentry_auth_token=" + value }},
		{name: "web3 private", category: "web3", pattern: "web3_private_key", value: "0x" + hex64, content: func(value string) string { return "private_key=" + value }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := categoryDetector(t, test.category)
			findings, err := detector.DetectSecrets(test.content(test.value), "file://production/provider.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.pattern, test.value)

			for _, continuation := range []string{"Z", "_", "-"} {
				continued, err := detector.DetectSecrets(test.content(test.value+continuation), "file://production/provider.env")
				if err != nil {
					t.Fatal(err)
				}
				for _, finding := range continued {
					if finding.Type == test.pattern {
						t.Fatalf("%s captured a truncated prefix before %q: %+v", test.pattern, continuation, continued)
					}
				}
			}
		})
	}
}

func TestStructuredFormatsRejectUnderscoreSuffixTruncation(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	tests := []struct {
		name     string
		category string
		pattern  string
		value    string
		content  func(string) string
	}{
		{name: "aws secret", category: "aws", pattern: "aws_secret_key", value: providerFixture(40), content: func(value string) string { return "AWS_SECRET_ACCESS_KEY=" + value }},
		{name: "cloudflare typed", category: "cloud", pattern: "cloudflare_api_token", value: "cfk_" + providerFixture(40) + "abcdef12", content: func(value string) string { return value }},
		{name: "heroku uuid", category: "cloud", pattern: "heroku_api_key", value: "123e4567-e89b-12d3-a456-426614174000", content: func(value string) string { return "HEROKU_API_KEY=" + value }},
		{name: "ipv6", category: "pii", pattern: "ipv6_address", value: "2606:4700:4700::1111", content: func(value string) string { return "ipv6_address=" + value }},
		{name: "mailgun", category: "communication", pattern: "mailgun_api_key", value: "key-" + providerFixture(32), content: func(value string) string { return value }},
		{name: "mapbox", category: "cloud", pattern: "mapbox_secret_token", value: "sk." + providerFixture(80), content: func(value string) string { return value }},
		{name: "slack", category: "code", pattern: "slack_token", value: "xoxb-" + providerFixture(48), content: func(value string) string { return value }},
		{name: "slack rotating", category: "code", pattern: "slack_rotating_token", value: "xoxe.xoxb-" + providerFixture(48), content: func(value string) string { return value }},
		{name: "slack refresh", category: "code", pattern: "slack_refresh_token", value: "xoxe-" + providerFixture(48), content: func(value string) string { return value }},
		{name: "sentry control", category: "observability", pattern: "sentry_legacy_auth_token", value: hex64, content: func(value string) string { return "sentry_auth_token=" + value }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := categoryDetector(t, test.category)
			findings, err := detector.DetectSecrets(test.content(test.value), "file://production/provider.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.pattern, test.value)

			continued, err := detector.DetectSecrets(test.content(test.value+"_suffix"), "file://production/provider.env")
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range continued {
				if finding.Type == test.pattern {
					t.Fatalf("%s captured a truncated prefix before _suffix: %+v", test.pattern, continued)
				}
			}
		})
	}
}

func TestGitHubFineGrainedTokenKeepsExactValue(t *testing.T) {
	detector := categoryDetector(t, "code")
	suffix := strings.Repeat("Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk", 3)[:82]
	value := "github_pat_" + suffix
	findings, err := detector.DetectSecrets(`token = "`+value+`"`, "file://production/config.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "github_fine_grained_token" {
			if finding.Value != value {
				t.Fatalf("GitHub token included a delimiter: %q", finding.Value)
			}
			return
		}
	}
	t.Fatalf("GitHub fine-grained token was rejected: %+v", findings)
}

func TestProviderScopedPublicIdentifiersAreRejected(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	content := strings.Join([]string{
		`algolia_searchOnlyKey = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"`,
		`pusher_public_app_key = "a7kq9mx2vr5ty8up3nd6"`,
	}, "\n")
	findings, err := detector.DetectSecrets(content, "file://production/frontend.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "algoliaadminkey_2" || finding.Type == "pusherchannelkey_2" {
			t.Fatalf("public identifier was classified as a secret: %+v", finding)
		}
	}
}

func TestProviderScopedExplicitSecretsRemainDetectable(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	algolia := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	pusher := "a7kq9mx2vr5ty8up3nd6"
	content := `algolia_admin_key = "` + algolia + `"` + "\n" +
		`pusher_app_secret = "` + pusher + `"`
	findings, err := detector.DetectSecrets(content, "file://production/backend.env")
	if err != nil {
		t.Fatal(err)
	}
	assertFinding := func(patternName, value string) {
		t.Helper()
		for _, finding := range findings {
			if finding.Type == patternName && finding.Value == value {
				return
			}
		}
		t.Errorf("missing %s finding for %q: %+v", patternName, value, findings)
	}
	assertFinding("algoliaadminkey_2", algolia)
	assertFinding("pusherchannelkey_2", pusher)
}

func TestLooseProviderValidationUsesTheMatchedOccurrence(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	value := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	content := `algolia search_index = "` + value + `";` + strings.Repeat(" ", 50) +
		`algolia_admin_key = "` + value + `"`
	findings, err := detector.DetectSecrets(content, "file://production/algolia.js")
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, finding := range findings {
		if finding.Type == "algoliaadminkey_2" && finding.Value == value {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected only the credential-labeled occurrence, got %d: %+v", count, findings)
	}
}

func TestLLMProviderContextPreventsOpenAIMisclassification(t *testing.T) {
	detector := categoryDetector(t, "llm")
	value := "sk-A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	findings, err := detector.DetectSecrets(`KIMI_API_KEY="`+value+`"`, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	foundKimi := false
	for _, finding := range findings {
		if finding.Value != value {
			continue
		}
		switch finding.Type {
		case "llm_kimi_moonshot_api_key":
			foundKimi = true
		case "llm_openai_api_key", "llm_openai_legacy_api_key":
			t.Fatalf("Kimi key was mislabeled as OpenAI: %+v", findings)
		}
	}
	if !foundKimi {
		t.Fatalf("Kimi key was not detected: %+v", findings)
	}
}

func TestNestedLLMProviderConfigurationKeepsImmediateProviderContext(t *testing.T) {
	detector := categoryDetector(t, "llm")
	kimi := "sk-A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	qwen := "sk-B8mR4nY3wS6uZ9vQ2dM5eC7iG1kX0aF3"
	content := "providers: {\n  moonshot: {\n    api_key: \"" + kimi + "\"\n  },\n  qwen: {\n    api_key: \"" + qwen + "\"\n  }\n}"

	findings, err := detector.DetectSecrets(content, "file://production/llm.json")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "llm_kimi_moonshot_api_key", kimi)
	assertProviderFinding(t, findings, "llm_qwen_dashscope_api_key", qwen)
	for _, finding := range findings {
		if finding.Value == kimi && finding.Type == "llm_qwen_dashscope_api_key" ||
			finding.Value == qwen && finding.Type == "llm_kimi_moonshot_api_key" {
			t.Fatalf("nested provider context leaked across siblings: %+v", findings)
		}
	}
}

func TestAdjacentLLMProvidersUseOnlyTheMatchedAssignmentContext(t *testing.T) {
	detector := categoryDetector(t, "llm")
	kimi := "sk-A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	qwen := "sk-B8mR4nY3wS6uZ9vQ2dM5eC7iG1kX0aF3"
	content := `KIMI_API_KEY="` + kimi + `"; QWEN_API_KEY="` + qwen + `"`
	findings, err := detector.DetectSecrets(content, "file://production/llm.env")
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		kimi: "llm_kimi_moonshot_api_key",
		qwen: "llm_qwen_dashscope_api_key",
	}
	counts := make(map[string]int)
	for _, finding := range findings {
		want, tracked := expected[finding.Value]
		if !tracked {
			continue
		}
		if finding.Type != want {
			t.Errorf("%q was mislabeled as %s, want %s", finding.Value, finding.Type, want)
		}
		counts[finding.Value]++
	}
	for value := range expected {
		if counts[value] != 1 {
			t.Errorf("%q produced %d provider findings: %+v", value, counts[value], findings)
		}
	}
}

func TestLLMRequiredContextUsesIdentifierBoundaries(t *testing.T) {
	detector := categoryDetector(t, "llm")
	first := "sk-A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	second := "sk-B8mR4nY3wS6uZ9vQ2dM5eC7iG1kX0aF3"
	noise := `DARK_API_KEY="` + first + `"; LANDMARK_TOKEN="` + second + `"`
	findings, err := detector.DetectSecrets(noise, "file://production/llm.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "llm_doubao_ark_api_key" {
			t.Fatalf("ark matched inside an unrelated identifier: %+v", findings)
		}
	}

	valid, err := detector.DetectSecrets(`ARK_API_KEY="`+first+`"`, "file://production/llm.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, valid, "llm_doubao_ark_api_key", first)
}

func TestOpenAIProjectKeyDoesNotNeedContext(t *testing.T) {
	detector := categoryDetector(t, "llm")
	value := "sk-proj-" + strings.Repeat("A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2", 2)
	findings, err := detector.DetectSecrets(`credential="`+value+`"`, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "llm_openai_api_key" && finding.Value == value {
			return
		}
	}
	t.Fatalf("OpenAI project key was rejected: %+v", findings)
}

func TestAWSTemporaryAccessKeyIDIsRecognized(t *testing.T) {
	detector := categoryDetector(t, "aws")
	value := "ASIA0123456789ABCDEF"
	findings, err := detector.DetectSecrets("AWS_ACCESS_KEY_ID="+value, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "aws_access_key" && finding.Value == value {
			return
		}
	}
	t.Fatalf("temporary AWS access key ID was rejected: %+v", findings)
}

func TestHerokuUUIDUsesIdentifierSeparatorsAndRejectsTruncation(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	value := "01234567-89ab-cdef-0123-456789abcdef"
	findings, err := detector.DetectSecrets("HEROKU_API_KEY="+value, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "heroku_api_key", value)

	truncated, err := detector.DetectSecrets("HEROKU_API_KEY="+value+"-extra", "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range truncated {
		if finding.Type == "heroku_api_key" {
			t.Fatalf("Heroku pattern captured a UUID prefix from a longer identifier: %+v", truncated)
		}
	}
}

func TestSecretAlphabetsWithSlashesAreNotClassifiedAsPaths(t *testing.T) {
	awsDetector := categoryDetector(t, "aws")
	aws := "A7kQ9mX2vR5tY8uP3src/6cB1hF4jW0zE2qS5aC8"
	awsFindings, err := awsDetector.DetectSecrets("AWS_SECRET_ACCESS_KEY="+aws, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, awsFindings, "aws_secret_key", aws)
	leadingSlashAWS := "/" + strings.Repeat("Ab3+Cd6/Ef9=Gh2Ij5Kl8Mn1Op4Qr7St0Uv", 2)[:39]
	awsFindings, err = awsDetector.DetectSecrets("AWS_SECRET_ACCESS_KEY="+leadingSlashAWS, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, awsFindings, "aws_secret_key", leadingSlashAWS)

	borgDetector := categoryDetector(t, "cloud")
	borg := (strings.Repeat("Ab3dEf6hIj9kLm2nOp5qRs8t", 7))[:150] + "/."
	borgFindings, err := borgDetector.DetectSecrets("BORGBASE_API_KEY="+borg, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, borgFindings, "borgbase", borg)

	continued, err := borgDetector.DetectSecrets("BORGBASE_API_KEY="+borg+"-", "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range continued {
		if finding.Type == "borgbase" {
			t.Fatalf("BorgBase pattern captured a truncated prefix: %+v", continued)
		}
	}
}

func TestDetectionOrderIsStable(t *testing.T) {
	detector := categoryDetector(t, "code")
	content := strings.Join([]string{
		"gho_" + strings.Repeat("A7kQ9mX2", 5)[:36],
		"glpat-" + strings.Repeat("B8mR4nY3", 3)[:20],
		"npm_" + strings.Repeat("C9pS5oZ4", 5),
	}, "\n")

	var baseline []string
	for iteration := 0; iteration < 20; iteration++ {
		findings, err := detector.DetectSecrets(content, "file://production/providers.env")
		if err != nil {
			t.Fatal(err)
		}
		order := make([]string, 0, len(findings))
		for _, finding := range findings {
			order = append(order, finding.Type+"\x00"+finding.Value)
		}
		if iteration == 0 {
			baseline = order
			continue
		}
		if !reflect.DeepEqual(order, baseline) {
			t.Fatalf("detection order changed: first=%v current=%v", baseline, order)
		}
	}
}

func TestLooseProviderRequiredContextAcceptsExactProviderLabels(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	tests := []struct {
		pattern string
		label   string
		value   string
	}{
		{pattern: "customerio", label: "CUSTOMERIO_API_KEY", value: "A7kQ9mX2vR5tY8uP3nD6"},
		{pattern: "lessannoyingcrm", label: "LESSANNOYINGCRM_API_KEY", value: strings.Repeat("A7kQ9mX2", 8)[:57]},
		{pattern: "surveyanyplace_1", label: "SURVEYANYPLACE_API_KEY", value: strings.Repeat("B8mR4nY3", 5)[:36]},
	}

	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			findings, err := detector.DetectSecrets(test.label+"="+test.value, "file://production/providers.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.pattern, test.value)
		})
	}
}

func TestLooseProviderTokenAlphabetsDoNotCapturePrefixes(t *testing.T) {
	detector := categoryDetector(t, "cloud")
	for _, test := range []struct {
		pattern string
		label   string
		value   string
	}{
		{pattern: "dynalist", label: "DYNALIST_API_KEY", value: strings.Repeat("A7kQ9mX2", 16)},
		{pattern: "surveysparrow", label: "SURVEYSPARROW_API_KEY", value: strings.Repeat("B8mR4nY3", 11)},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			findings, err := detector.DetectSecrets(test.label+"="+test.value, "file://production/providers.env")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderFinding(t, findings, test.pattern, test.value)

			continued, err := detector.DetectSecrets(test.label+"="+test.value+"-", "file://production/providers.env")
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range continued {
				if finding.Type == test.pattern {
					t.Fatalf("%s captured a truncated prefix: %+v", test.pattern, continued)
				}
			}
		})
	}
}

func TestBasicAuthDoesNotCaptureAnOversizedPrefix(t *testing.T) {
	detector := categoryDetector(t, "auth")
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("service-account:correct-horse-battery-staple"))
	findings, err := detector.DetectSecrets("Authorization: "+credential, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "basic_auth", credential)

	oversized := "Basic " + strings.Repeat("A", 101)
	findings, err = detector.DetectSecrets("Authorization: "+oversized, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "basic_auth" {
			t.Fatalf("Basic auth captured a truncated prefix: %+v", findings)
		}
	}
}

func TestTwilioAPIKeyRequiresTokenBoundaries(t *testing.T) {
	detector := categoryDetector(t, "communication")
	value := "SK0123456789abcdef0123456789abcdef"
	findings, err := detector.DetectSecrets("TWILIO_API_KEY="+value, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "twilio_api_key", value)

	findings, err = detector.DetectSecrets("X"+value+"Y", "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "twilio_api_key" {
			t.Fatalf("Twilio API key matched inside a longer identifier: %+v", findings)
		}
	}
}

func TestGoogleOAuthClientIDRequiresACompleteDomainBoundary(t *testing.T) {
	detector := categoryDetector(t, "gcp")
	value := "123-" + strings.Repeat("A7kQ9mX2", 4) + ".apps.googleusercontent.com"
	findings, err := detector.DetectSecrets("google_client_id="+value, "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "google_cloud_platform", value)

	findings, err = detector.DetectSecrets("google_client_id="+value+"pany", "file://production/config.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "google_cloud_platform" {
			t.Fatalf("Google OAuth client ID captured a .com prefix from a longer domain: %+v", findings)
		}
	}
}

func TestGenericAssignmentRejectsEnvironmentReference(t *testing.T) {
	detector := categoryDetector(t, "generic")
	fallback := "R5mQ8xV2nT7yU1pL9cD4bH6jF3kW0zE2"
	findings, err := detector.DetectSecrets(
		`const api_key = process.env.API_KEY || "`+fallback+`";`,
		"file://production/config.js",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Value == "process.env.API_KEY" {
			t.Fatalf("environment reference was emitted as a secret: %+v", findings)
		}
	}
	assertProviderFinding(t, findings, "api_key_assignment", fallback)
}

func TestGenericAssignmentPreservesOpaqueValueWithFileSuffix(t *testing.T) {
	detector := categoryDetector(t, "generic")
	value := "AbCdEf0123456789.json"
	findings, err := detector.DetectSecrets(`api_key="`+value+`"`, "file://production/config.js")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "api_key_assignment", value)
}
