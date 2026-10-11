package utils

import "testing"

func TestLikelyFilePathDistinguishesAssetsFromCredentialURIs(t *testing.T) {
	for _, value := range []string{
		"assets.runtime.chunk.js",
		"dist/app.min.js",
		"src\\assets\\main.css",
		"node_modules/pkg/index",
		"/etc/passwd",
		`C:\repo\secrets\config`,
	} {
		if !IsLikelyFilePath(value) {
			t.Errorf("asset path %q was not recognized", value)
		}
	}

	for _, value := range []string{
		"postgresql://deploy:AbCdEf012345@db.internal/orders",
		"redis://deploy:AbCdEf012345@cache.internal:6379",
		"https://hooks.slack.com/services/T12345678/B12345678/AbCdEf0123456789AbCdEf01",
		"AbCdEf0123456789.AbCdEf0123456789",
		"AbCdEf0123456789.json",
		"A7kQ9mX2vR5tY8uP3src/6cB1hF4jW0zE2q",
		"A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0z.E2/qS5aC8",
		"/Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3",
	} {
		if IsLikelyFilePath(value) {
			t.Errorf("credential value %q was classified as a file path", value)
		}
	}
}

func TestURLSchemeAloneDoesNotImplyDocumentation(t *testing.T) {
	value := "https://hooks.slack.com/services/T12345678/B12345678/AbCdEf0123456789AbCdEf01"
	if IsLikelyDocumentation(value, "SLACK_WEBHOOK="+value) {
		t.Fatal("credential URL was classified as documentation from its scheme alone")
	}
	if !IsLikelyDocumentation(value, "Example from the integration documentation: "+value) {
		t.Fatal("explicit documentation context was not recognized")
	}
}
