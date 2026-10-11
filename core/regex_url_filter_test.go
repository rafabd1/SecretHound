package core

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestFindSecretsScansAllPatternsInMinifiedJavaScript(t *testing.T) {
	regexManager := regexManagerWithURLAndSecretPatterns(t, "minified_secret", `secret\s*=\s*"([A-Za-z0-9]{24})"`)
	urlValue := "https://api.production.dev/v1/users"
	content := `const endpoint = "` + urlValue + `"; secret = "Ab3dEf6hIj9kLm2nOp5qRs8t";`

	findings, err := regexManager.FindSecrets(content, "https://cdn.production.dev/assets/app.min.js")
	if err != nil {
		t.Fatal(err)
	}
	if !containsSecretFinding(findings, "url_generic", urlValue) {
		t.Fatalf("URL pattern did not scan an excluded JavaScript source: %+v", findings)
	}
	if !containsSecretType(findings, "minified_secret") {
		t.Fatalf("secret pattern did not scan minified JavaScript: %+v", findings)
	}
}

func TestFindSecretsUsesPatternSpecificLengthBounds(t *testing.T) {
	regexManager := regexManagerWithURLAndSecretPatterns(t, "long_secret", `secret\s*=\s*"([A-Za-z0-9]{220})"`)
	urlValue := "https://api.production.dev/v1/" + strings.Repeat("segment-", 28) + "resource"
	secretValue := strings.Repeat("Ab3dEf6hIj9kLm2nOp5qRs8t", 10)[:220]
	content := `endpoint = "` + urlValue + `"; secret = "` + secretValue + `";`

	findings, err := regexManager.FindSecrets(content, "https://cdn.production.dev/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !containsSecretFinding(findings, "url_generic", urlValue) {
		t.Fatalf("URL longer than the secret limit was not returned: %+v", findings)
	}
	if !containsSecretType(findings, "long_secret") {
		t.Fatalf("pattern-specific 500-byte maximum was replaced by a global cap: %+v", findings)
	}
}

func TestProcessorNormalizesURLTrailingPunctuation(t *testing.T) {
	processor := NewProcessor(regexManagerWithURLPatterns(t), output.NewLogger(false, true))
	wanted := "https://api.production.dev/v1/users"

	findings, err := processor.ProcessJSContent("See "+wanted+").", "https://cdn.production.dev/index.html")
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, finding := range findings {
		if finding.Type != "url_generic" {
			continue
		}
		count++
		if finding.Value != wanted {
			t.Fatalf("URL was not normalized before emission: %q", finding.Value)
		}
	}
	if count != 1 {
		t.Fatalf("got %d normalized URL findings, expected 1: %+v", count, findings)
	}
}

func TestProcessorNormalizesDirectURLTrailingPunctuation(t *testing.T) {
	processor := NewProcessor(regexManagerWithURLPatterns(t), output.NewLogger(false, true))
	wanted := "https://api.production.dev/v1/users"

	findings, err := processor.ProcessJSContent("See "+wanted+", then continue.", "https://cdn.production.dev/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !containsSecretFinding(findings, "url_generic", wanted) {
		t.Fatalf("normalized URL was not emitted: %+v", findings)
	}
	if containsSecretFinding(findings, "url_generic", wanted+",") {
		t.Fatalf("URL kept trailing prose punctuation: %+v", findings)
	}
}

func TestProcessorExtractsBothMarkdownLinkURLs(t *testing.T) {
	processor := NewProcessor(regexManagerWithURLPatterns(t), output.NewLogger(false, true))
	content := `[http://text.example](https://target.example)`

	findings, err := processor.ProcessJSContent(content, "file:///README.md")
	if err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"http://text.example", "https://target.example"} {
		if !containsSecretFinding(findings, "url_generic", value) {
			t.Errorf("missing Markdown URL %q; got %+v", value, findings)
		}
	}
}

func TestProcessorEmitsShortCapturedPathOnceAndRejectsMalformedURI(t *testing.T) {
	processor := NewProcessor(regexManagerWithURLPatterns(t), output.NewLogger(false, true))
	content := `short = "/a"; broken = "http://%zz";`

	findings, err := processor.ProcessJSContent(content, "file:///config.js")
	if err != nil {
		t.Fatal(err)
	}

	pathCount := 0
	for _, finding := range findings {
		switch finding.Type {
		case "url_path":
			pathCount++
			if finding.Value != "/a" {
				t.Fatalf("URL path included quotes or the full regex match: %q", finding.Value)
			}
		case "url_generic":
			t.Fatalf("malformed URI was emitted: %q", finding.Value)
		}
	}
	if pathCount != 1 {
		t.Fatalf("got %d short path findings, expected exactly 1: %+v", pathCount, findings)
	}
}

func regexManagerWithURLPatterns(t *testing.T) *RegexManager {
	t.Helper()
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{"url"}, nil); err != nil {
		t.Fatalf("load URL patterns: %v", err)
	}

	regexManager := NewRegexManager()
	regexManager.SetPatternManager(manager)
	return regexManager
}

func regexManagerWithURLAndSecretPatterns(t *testing.T, secretName, secretRegex string) *RegexManager {
	t.Helper()
	regexManager := regexManagerWithURLPatterns(t)
	if err := regexManager.patternManager.AddPattern(secretName, secretRegex, "test secret"); err != nil {
		t.Fatalf("add secret pattern: %v", err)
	}
	return regexManager
}

func containsSecretFinding(findings []Secret, findingType, value string) bool {
	for _, finding := range findings {
		if finding.Type == findingType && finding.Value == value {
			return true
		}
	}
	return false
}

func containsSecretType(findings []Secret, findingType string) bool {
	for _, finding := range findings {
		if finding.Type == findingType {
			return true
		}
	}
	return false
}
