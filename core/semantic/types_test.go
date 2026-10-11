package semantic

import "testing"

func TestReviewModeForCategory(t *testing.T) {
	tests := map[string]ReviewMode{
		"url":     ReviewModeBypass,
		" URL ":   ReviewModeBypass,
		"bash":    ReviewModeBypass,
		"BASH":    ReviewModeBypass,
		"pii":     ReviewModePII,
		" PII ":   ReviewModePII,
		"":        ReviewModeSecret,
		"auth":    ReviewModeSecret,
		"generic": ReviewModeSecret,
	}
	for category, expected := range tests {
		if actual := ReviewModeForCategory(category); actual != expected {
			t.Errorf("category %q mode = %q, expected %q", category, actual, expected)
		}
	}
}
