package patterns

import (
	"strings"
	"testing"
)

func TestCompilePatternRegexRejectsTruncatedCapturedValues(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		inputPrefix string
		value       string
		extensions  []string
		punctuation string
	}{
		{
			name:        "hyphen remains part of token alphabet",
			expression:  `token=([a-z0-9-]{36})(?:[^A-Za-z0-9_]|$)`,
			inputPrefix: "token=",
			value:       strings.Repeat("a1-", 12),
			extensions:  []string{"-extra"},
			punctuation: ".",
		},
		{
			name:        "dot remains part of token alphabet",
			expression:  `token=([A-Za-z0-9._-]{8})(?:[^A-Za-z0-9_-]|$)`,
			inputPrefix: "token=",
			value:       "ab.cd_E1",
			extensions:  []string{".more"},
			punctuation: ",",
		},
		{
			name:        "base64 punctuation remains part of token alphabet",
			expression:  `token=([A-Za-z0-9/+=]{12})(?:[^A-Za-z0-9_]|$)`,
			inputPrefix: "token=",
			value:       "Ab1/Cd2+Ef3=",
			extensions:  []string{"/tail", "+tail", "=tail"},
			punctuation: ";",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			re, err := compilePatternRegex(test.expression)
			if err != nil {
				t.Fatalf("compilePatternRegex() error = %v", err)
			}

			assertCapturedValue(t, re.FindStringSubmatch(test.inputPrefix+test.value), test.value)
			assertCapturedValue(t, re.FindStringSubmatch(test.inputPrefix+test.value+test.punctuation), test.value)

			for _, extension := range test.extensions {
				if match := re.FindStringSubmatch(test.inputPrefix + test.value + extension); match != nil {
					t.Fatalf("truncated match for extension %q: %#v", extension, match)
				}
			}
		})
	}
}

func TestCompilePatternRegexLeavesSafeDelimiterBehaviorIntact(t *testing.T) {
	value := strings.Repeat("a1-", 12)
	re, err := compilePatternRegex(`prefix=([a-z0-9-]{36})(?:[^A-Za-z0-9_-]|$)`)
	if err != nil {
		t.Fatal(err)
	}

	assertCapturedValue(t, re.FindStringSubmatch("prefix="+value), value)
	assertCapturedValue(t, re.FindStringSubmatch("prefix="+value+"."), value)
	if match := re.FindStringSubmatch("prefix=" + value + "-extra"); match != nil {
		t.Fatalf("safe delimiter accepted an alphabet continuation: %#v", match)
	}
}

func TestPatternManagerAddPatternUsesHardenedDelimiter(t *testing.T) {
	manager := NewPatternManager()
	value := strings.Repeat("a1-", 12)
	if err := manager.AddPattern(
		"boundary_guard_test",
		`token=([a-z0-9-]{36})(?:[^A-Za-z0-9_]|$)`,
		"boundary guard test",
	); err != nil {
		t.Fatal(err)
	}

	compiled := manager.GetCompiledPatterns()["boundary_guard_test"]
	if compiled == nil {
		t.Fatal("added pattern was not compiled")
	}
	if match := compiled.Regex.FindStringSubmatch("token=" + value + "-extra"); match != nil {
		t.Fatalf("manager compiled a truncated capture: %#v", match)
	}
	assertCapturedValue(t, compiled.Regex.FindStringSubmatch("token="+value+"."), value)
}

func TestCatalogBoundedPatternsRejectTokenExtensions(t *testing.T) {
	manager := NewPatternManager()
	if err := manager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	compiled := manager.GetCompiledPatterns()

	tests := []struct {
		name           string
		value          string
		extensions     []string
		leftExtensions []string
	}{
		{
			name:           "bearer_token",
			value:          "Bearer " + boundaryFixture(500),
			extensions:     []string{"A", "-tail"},
			leftExtensions: []string{"x", "_"},
		},
		{
			name:           "braintree_token",
			value:          "access_token$production$a1b2c3d4e5f60718$" + strings.Repeat("a1b2c3d4", 4),
			leftExtensions: []string{"x", "_"},
			extensions: []string{
				"a",
				"_tail",
			},
		},
		{
			name:           "mailchimp_api_key",
			value:          strings.Repeat("a1b2c3d4", 4) + "-us12",
			extensions:     []string{"3", "_tail"},
			leftExtensions: []string{"x", "_"},
		},
		{
			name: "slack_webhook",
			value: "https://hooks.slack.com/services/T" + boundaryFixture(8) +
				"/B" + boundaryFixture(8) + "/" + boundaryFixture(32),
			extensions:     []string{"A", "_tail"},
			leftExtensions: []string{"x", "_"},
		},
		{
			name:           "discord_webhook",
			value:          "https://discord.com/api/webhooks/1234567890123456789/" + boundaryFixture(68),
			leftExtensions: []string{"x", "_"},
		},
		{
			name:       "telegram_bot_token",
			value:      "12345678:" + boundaryFixture(35),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "mapbox_secret_token",
			value:      "sk." + boundaryFixture(240),
			extensions: []string{"A", ".tail"},
		},
		{
			name:       "huggingface_api_token",
			value:      "hf_" + boundaryFixture(34),
			extensions: []string{"A", "_tail"},
		},
		{
			name:           "github_fine_grained_token",
			value:          "github_pat_" + boundaryFixture(82),
			extensions:     []string{"A", "_tail"},
			leftExtensions: []string{"x", "_"},
		},
		{
			name:       "llm_anthropic_api_key",
			value:      "sk-ant-api03-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_groq_api_key",
			value:      "gsk_" + boundaryFixture(200),
			extensions: []string{"A", "_tail"},
		},
		{
			name:       "llm_xai_grok_api_key",
			value:      "xai-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_kimi_moonshot_api_key",
			value:      "sk-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_qwen_dashscope_api_key",
			value:      "sk-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_zhipu_glm_api_key",
			value:      boundaryFixture(32) + "." + boundaryFixture(16),
			extensions: []string{"A", ".tail", "-tail", "_tail"},
		},
		{
			name:       "llm_doubao_ark_api_key",
			value:      "ark-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_openrouter_api_key",
			value:      "sk-or-v1-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_perplexity_api_key",
			value:      "pplx-" + boundaryFixture(200),
			extensions: []string{"A", "-tail", "_tail"},
		},
		{
			name:       "llm_replicate_api_token",
			value:      "r8_" + boundaryFixture(200),
			extensions: []string{"A", "_tail"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pattern := compiled[test.name]
			if pattern == nil {
				t.Fatalf("pattern %q was not loaded", test.name)
			}

			assertCapturedValue(t, pattern.Regex.FindStringSubmatch(test.value), test.value)
			assertCapturedValue(t, pattern.Regex.FindStringSubmatch(test.value+","), test.value)
			for _, extension := range test.extensions {
				if match := pattern.Regex.FindStringSubmatch(test.value + extension); match != nil {
					t.Fatalf("pattern accepted extension %q as a truncated value: %#v", extension, match)
				}
			}
			for _, extension := range test.leftExtensions {
				if match := pattern.Regex.FindStringSubmatch(extension + test.value); match != nil {
					t.Fatalf("pattern accepted left extension %q as a suffix match: %#v", extension, match)
				}
			}
		})
	}
}

func TestCatalogLabelPatternsRejectEmbeddedSuffixes(t *testing.T) {
	manager := NewPatternManager()
	compiled := manager.GetCompiledPatterns()

	pan := "6011000990139424"
	if match := compiled["credit_card_number"].Regex.FindStringSubmatch("japan=" + pan); match != nil {
		t.Fatalf("PAN label matched inside another identifier: %#v", match)
	}
	assertCapturedValue(t, compiled["credit_card_number"].Regex.FindStringSubmatch("pan="+pan), pan)

	session := boundaryFixture(44)
	if match := compiled["session_token"].Regex.FindStringSubmatch(`SSID="` + session + `"`); match != nil {
		t.Fatalf("sid label matched inside SSID: %#v", match)
	}
	assertCapturedValue(t, compiled["session_token"].Regex.FindStringSubmatch(`SID="`+session+`"`), session)
}

func boundaryFixture(length int) string {
	const seed = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	return strings.Repeat(seed, length/len(seed)+1)[:length]
}

func assertCapturedValue(t *testing.T, match []string, expected string) {
	t.Helper()
	if len(match) < 2 {
		t.Fatalf("missing capture for %q: %#v", expected, match)
	}
	if match[1] != expected {
		t.Fatalf("capture = %q, want %q", match[1], expected)
	}
}
