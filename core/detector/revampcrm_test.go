package detector

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestRevampCRMRejectsNearbyCodeIdentifiers(t *testing.T) {
	detector := newCloudDetector(t)
	content := `
"modules.delivery.shipping-template-revamp.form-error-global": "message",
"application.auth.email.sub": "prompt",
const modes = {pickupPoint:K.modePickupPoint, homeDelivery:K.modeHomeDelivery};
`

	findings, err := detector.DetectSecrets(content, "https://example.test/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "revampcrm_2" {
			t.Fatalf("code identifier emitted as RevampCRM token: %q", finding.Value)
		}
	}
}

func TestRevampCRMDetectsFortyCharacterToken(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	content := `const revampcrm_token = "` + token + `";`

	findings, err := detector.DetectSecrets(content, "file:///config.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "revampcrm_2" && finding.Value == token {
			return
		}
	}
	t.Fatalf("RevampCRM token was not detected: %+v", findings)
}

func TestRevampCRMDetectsNestedProviderConfiguration(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	for _, content := range []string{
		`revampcrm: { token: "` + token + `" }`,
		"revampcrm: {\n  token: \"" + token + "\"\n}",
		"\"revampcrm\": {\n  \"api_key\": \"" + token + "\"\n}",
		`revampcrm: { x: 1, token: "` + token + `" }`,
		"revampcrm: {\n  x: 1,\n  token: \"" + token + "\"\n}",
		"\"revampcrm\": {\n  \"x\": 1,\n  \"api_key\": \"" + token + "\"\n}",
		"revampcrm: { note: `},,`, token: \"" + token + "\" }",
	} {
		findings, err := detector.DetectSecrets(content, "file:///config.js")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" && finding.Value == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("nested RevampCRM token was not detected in %q: %+v", content, findings)
		}
	}
}

func TestRevampCRMMultilineProviderContextDoesNotLeakToSibling(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	for _, content := range []string{
		"revampcrm: {\n  public_id: \"frontend\"\n}\napi_key: \"" + token + "\"",
		"revampcrm: {\n  nested: {\n    token: \"" + token + "\"\n  }\n}",
		"revampcrm: { nested: [ { token: \"" + token + "\" } ] }",
	} {
		findings, err := detector.DetectSecrets(content, "file:///config.js")
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" {
				t.Errorf("RevampCRM provider context leaked outside its direct object: %+v", findings)
			}
		}
	}
}

func TestRevampCRMDetectsDirectProviderCredentialLabels(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"

	for _, content := range []string{
		`revampcrm_key = "` + token + `"`,
		`revampcrmKey = "` + token + `"`,
		`revampcrm_token = "` + token + `"`,
		`revampcrmApiKey = "` + token + `"`,
		`revampcrmAPIKey = "` + token + `"`,
		`revampcrmAPIToken = "` + token + `"`,
		`revampcrm-api-key: "` + token + `"`,
		`revampcrm.key = "` + token + `"`,
		`"revampcrm_api_key": "` + token + `"`,
		`'revampcrm-token' = '` + token + `'`,
		`revampcrm["api_key"] = "` + token + `"`,
		`revampcrm['token'] = '` + token + `'`,
		`revampcrm: { key: "` + token + `" }`,
	} {
		findings, err := detector.DetectSecrets(content, "file:///config.js")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" && finding.Value == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bare provider key label was not detected in %q: %+v", content, findings)
		}
	}
}

func TestRevampCRMDirectProviderContextRejectsIntermediateSyntax(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	pattern := detector.patternManager.GetCompiledPatterns()["revampcrm_2"]
	if pattern == nil {
		t.Fatal("revampcrm_2 pattern was not loaded")
	}

	for _, content := range []string{
		`revampcrm = false; api_key = "` + token + `"`,
		`revampcrm = false, token = "` + token + `"`,
		`revampcrm(false).api_key = "` + token + `"`,
		`revampcrm] api_key = "` + token + `"`,
		`revampcrm helper api_key = "` + token + `"`,
		`revampcrm.other.api_key = "` + token + `"`,
		`revampcrm_key_suffix = "` + token + `"`,
		`revampcrm = "` + token + `"`,
	} {
		if !pattern.Regex.MatchString(content) {
			t.Fatalf("negative fixture did not reach validation: %q", content)
		}
		findings, err := detector.DetectSecrets(content, "file:///config.js")
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" {
				t.Errorf("RevampCRM context crossed intermediate syntax in %q: %+v", content, findings)
			}
		}
	}
}

func TestRevampCRMProviderBoundaryRejectsUnicodeIdentifierEmbedding(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	pattern := detector.patternManager.GetCompiledPatterns()["revampcrm_2"]
	if pattern == nil {
		t.Fatal("revampcrm_2 pattern was not loaded")
	}

	for _, content := range []string{
		`érevampcrmApiKey = "` + token + `"`,
		`érevampcrmApiKey = "` + token + `"`,
		`revampcrméApiKey = "` + token + `"`,
		`revampcrmÉApiKey = "` + token + `"`,
	} {
		if !pattern.Regex.MatchString(content) {
			t.Fatalf("Unicode boundary fixture did not reach validation: %q", content)
		}
		findings, err := detector.DetectSecrets(content, "file:///config.js")
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" {
				t.Errorf("RevampCRM provider matched inside Unicode identifier %q: %+v", content, findings)
			}
		}
	}
}

func TestRevampCRMDetectsStrictYAMLProviderCredential(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"

	for _, content := range []string{
		"revampcrm:\n  token: \"" + token + "\"",
		"  \"revampcrm\":\r\n    \"api_key\": '" + token + "'\r\n",
		"'revampcrm':\n\n  api-token: " + token + "\n",
	} {
		findings, err := detector.DetectSecrets(content, "file:///config.yaml")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range findings {
			if finding.Type == "revampcrm_2" && finding.Value == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("strict YAML RevampCRM token was not detected in %q: %+v", content, findings)
		}
	}
}

func TestRevampCRMRejectsAmbiguousYAMLProviderContext(t *testing.T) {
	detector := newCloudDetector(t)
	const token = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
	pattern := detector.patternManager.GetCompiledPatterns()["revampcrm_2"]
	if pattern == nil {
		t.Fatal("revampcrm_2 pattern was not loaded")
	}

	tests := []struct {
		name    string
		content string
	}{
		{name: "comment before credential", content: "revampcrm:\n  # token\n  token: \"" + token + "\""},
		{name: "list item", content: "revampcrm:\n  - token: \"" + token + "\""},
		{name: "field before credential", content: "revampcrm:\n  mode: x\n  token: \"" + token + "\""},
		{name: "nested object", content: "revampcrm:\n  auth:\n    token: \"" + token + "\""},
		{name: "block scalar", content: "revampcrm:\n  token: |\n    " + token + "\n"},
		{name: "sibling dedent", content: "  revampcrm:\nother:\n token: \"" + token + "\""},
		{name: "provider not first token", content: "outer: revampcrm:\n  token: \"" + token + "\""},
		{name: "header comment", content: "revampcrm: # config\n  token: \"" + token + "\""},
		{name: "header trailing space", content: "revampcrm: \n  token: \"" + token + "\""},
		{name: "mismatched header quote", content: "\"revampcrm':\n  token: \"" + token + "\""},
		{name: "mismatched label quote", content: "revampcrm:\n  \"token': \"" + token + "\""},
		{name: "inline comment", content: "revampcrm:\n  token: \"" + token + "\" # config"},
		{name: "mismatched value quote", content: "revampcrm:\n  token: \"" + token + "'"},
		{name: "same indentation", content: "  revampcrm:\n  token: \"" + token + "\""},
		{name: "tab on blank line", content: "revampcrm:\n \t\n  token: \"" + token + "\""},
		{name: "tab indentation", content: "revampcrm:\n\ttoken: \"" + token + "\""},
		{name: "truncated line prefix", content: "outer:" + strings.Repeat(" ", 120) + "revampcrm:\n  token: \"" + token + "\""},
		{name: "truncated line suffix", content: "revampcrm:\n  token: \"" + token + "\"" + strings.Repeat(" ", 120) + "# config"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !pattern.Regex.MatchString(test.content) {
				t.Fatalf("negative YAML fixture did not reach validation: %q", test.content)
			}
			findings, err := detector.DetectSecrets(test.content, "file:///config.yaml")
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range findings {
				if finding.Type == "revampcrm_2" {
					t.Errorf("ambiguous YAML context emitted RevampCRM token: %+v", findings)
				}
			}
		})
	}
}

func newCloudDetector(t *testing.T) *Detector {
	t.Helper()
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{"cloud"}, nil); err != nil {
		t.Fatalf("load cloud patterns: %v", err)
	}
	return NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		ContextSize:   100,
		MinConfidence: 0.5,
	})
}
