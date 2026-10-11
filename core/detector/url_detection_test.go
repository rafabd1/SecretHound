package detector

import (
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestURLCategoryDetectsURIsDomainsAndEndpoints(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{"url"}, nil); err != nil {
		t.Fatalf("load URL patterns: %v", err)
	}
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		ContextSize:   100,
		MinConfidence: 0.5,
	})

	content := `
webhook = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX"
postgres = "postgresql://deploy:synthetic-password@db.internal/orders"
mongo = "mongodb+srv://deploy:synthetic-password@cluster.internal/orders"
redis = "redis://legacy:synthetic-password@cache.internal:6379"
mysql = "mysql://fixture:synthetic-password@localhost/example"
public_host = "cdn-assets.example.com"
asset_name = "assets.runtime.chunk.js"
endpoint = "/api/v1/users?active=true"
short_endpoint = "/a"
root_query = "/?page=2"
action_endpoint = "/api/users/42:activate"
nested_query = "/api/search?next=/users?page=2"
template_endpoint = ` + "`/api/v2/accounts/${accountId}`" + `
prose = "See https://api.example.com/v1/users)."
malformed = "https://[::1"
`

	findings, err := detector.DetectSecrets(content, "file:///config.js")
	if err != nil {
		t.Fatal(err)
	}

	found := make(map[string]bool, len(findings))
	for _, item := range findings {
		found[item.Type+"\x00"+item.Value] = true
	}
	wanted := map[string]string{
		"url_generic": "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX",
		"postgres":    "postgresql://deploy:synthetic-password@db.internal/orders",
		"mongo":       "mongodb+srv://deploy:synthetic-password@cluster.internal/orders",
		"redis":       "redis://legacy:synthetic-password@cache.internal:6379",
		"mysql":       "mysql://fixture:synthetic-password@localhost/example",
	}
	for label, value := range wanted {
		if !found["url_generic\x00"+value] {
			t.Errorf("missing %s URI %q", label, value)
		}
	}
	if !found["generic_domain_name\x00cdn-assets.example.com"] {
		t.Error("missing public domain")
	}
	if !found["url_path\x00/api/v1/users?active=true"] {
		t.Error("missing quoted endpoint")
	}
	if !found["url_path\x00/a"] {
		t.Error("missing short quoted endpoint")
	}
	for _, value := range []string{"/?page=2", "/api/users/42:activate", "/api/search?next=/users?page=2"} {
		if !found["url_path\x00"+value] {
			t.Errorf("missing endpoint %q", value)
		}
	}
	if !found["url_path\x00/api/v2/accounts/${accountId}"] {
		t.Error("missing endpoint in a template literal")
	}
	if !found["url_generic\x00https://api.example.com/v1/users"] {
		t.Error("missing normalized URI")
	}
	if found["url_generic\x00https://api.example.com/v1/users)."] {
		t.Error("URI kept trailing prose punctuation")
	}
	if found["url_generic\x00https://[::1"] {
		t.Error("malformed URI was emitted")
	}
	if found["generic_domain_name\x00assets.runtime.chunk.js"] {
		t.Error("asset filename was emitted as a domain")
	}
}

func TestURLCategoryExtractsMarkdownLinksWithoutBreakingURIDelimiters(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{"url"}, nil); err != nil {
		t.Fatalf("load URL patterns: %v", err)
	}
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		ContextSize:   100,
		MinConfidence: 0.5,
	})

	content := `
[docs](https://docs.example.com/guide)
[http://text.example](https://target.example)
ipv6 = "https://[2001:db8::1]/wiki/Function_(mathematics)"
brackets = "https://example.com/search?tag=[one]"
raw = "https://example.com/path)"
`
	findings, err := detector.DetectSecrets(content, "file:///README.md")
	if err != nil {
		t.Fatal(err)
	}

	found := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if finding.Type == "url_generic" {
			found[finding.Value] = true
		}
	}
	for _, value := range []string{
		"https://docs.example.com/guide",
		"http://text.example",
		"https://target.example",
		"https://[2001:db8::1]/wiki/Function_(mathematics)",
		"https://example.com/search?tag=[one]",
		"https://example.com/path)",
	} {
		if !found[value] {
			t.Errorf("missing URL %q; got %+v", value, findings)
		}
	}
	for value := range found {
		if value == "http://text.example](https://target.example)" ||
			value == "https://docs.example.com/guide)" {
			t.Errorf("emitted URL with Markdown syntax: %q", value)
		}
	}
}
