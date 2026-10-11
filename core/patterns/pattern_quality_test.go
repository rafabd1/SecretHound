package patterns

import (
	"regexp"
	"strings"
	"testing"
)

func TestPatternLengthBoundsAreConsistent(t *testing.T) {
	for name, cfg := range DefaultPatterns.Patterns {
		if cfg.MinLength < 0 {
			t.Errorf("pattern %q has negative minlength %d", name, cfg.MinLength)
		}
		if cfg.MaxLength < 0 {
			t.Errorf("pattern %q has negative maxlength %d", name, cfg.MaxLength)
		}
		if cfg.MinLength > 0 && cfg.MaxLength > 0 && cfg.MinLength > cfg.MaxLength {
			t.Errorf(
				"pattern %q has minlength %d greater than maxlength %d",
				name,
				cfg.MinLength,
				cfg.MaxLength,
			)
		}
		if cfg.UseEntropy && cfg.EntropyMinLength > 0 && cfg.MaxLength > 0 && cfg.EntropyMinLength > cfg.MaxLength {
			t.Errorf(
				"pattern %q has entropyminlength %d greater than maxlength %d",
				name,
				cfg.EntropyMinLength,
				cfg.MaxLength,
			)
		}
	}
}

func TestLoadablePatternRegexesPassMechanicalHygieneChecks(t *testing.T) {
	if DefaultPatterns == nil || len(DefaultPatterns.Patterns) == 0 {
		t.Fatal("embedded pattern catalog is empty")
	}

	// These fragments represent known character-class mistakes rather than
	// provider-specific format choices. Keep this list narrow to avoid turning
	// the test into a second regex parser.
	bannedFragments := map[string]string{
		"[0-9Aa-z]":      "mixed-case range omits most uppercase letters",
		"[0-9Aa-z-]":     "mixed-case range omits most uppercase letters",
		"[a-zA0-9]":      "uppercase range is missing its end",
		"[0-9Aa-f]":      "hex range is malformed",
		"[a-zA-Z0-9.-@]": "hyphen creates an unintended punctuation range",
		"[a-zA-Z0-9-_]":  "hyphen creates an unintended punctuation range",
		"[h|H]":          "alternation was written as a character class",
	}
	positiveClassWithNonSpace := regexp.MustCompile(`\[[^\]]*\\S[^\]]*\]`)

	for name, cfg := range DefaultPatterns.Patterns {
		if cfg.Retired {
			continue
		}
		if strings.TrimSpace(name) == "" {
			t.Error("enabled pattern has an empty name")
		}
		if strings.TrimSpace(cfg.Category) == "" {
			t.Errorf("pattern %q has an empty category", name)
		}

		raw := strings.TrimSpace(cfg.Regex)
		if raw == "" {
			t.Errorf("pattern %q has an empty regex", name)
			continue
		}
		if _, err := compilePatternRegex(raw); err != nil {
			t.Errorf("pattern %q does not compile: %v", name, err)
			continue
		}

		for fragment, reason := range bannedFragments {
			if strings.Contains(raw, fragment) {
				t.Errorf("pattern %q contains %q: %s", name, fragment, reason)
			}
		}
		for _, characterClass := range positiveClassWithNonSpace.FindAllString(raw, -1) {
			if !strings.HasPrefix(characterClass, "[^") {
				t.Errorf("pattern %q contains overbroad character class %q", name, characterClass)
			}
		}

		if strings.Contains(raw, ".{0,40}") && strings.HasSuffix(raw, `)\b`) {
			t.Errorf("loose provider pattern %q ends its captured value with a word boundary", name)
		}
		if strings.Contains(raw, ".{0,40}") && !strings.HasPrefix(raw, "(?i:") {
			t.Errorf("loose provider pattern %q does not match uppercase provider labels", name)
		}
	}
}

func TestKnownDuplicateAliasesAreNotEnabledTogether(t *testing.T) {
	for _, pair := range [][2]string{
		{"fmfw_1", "fmfw_2"},
		{"mixpanel_1", "mixpanel_2"},
		{"restpack", "restpackhtmltopdfapi"},
	} {
		left := DefaultPatterns.Patterns[pair[0]]
		right := DefaultPatterns.Patterns[pair[1]]
		if left.Enabled && right.Enabled {
			t.Errorf("duplicate patterns %q and %q are both enabled", pair[0], pair[1])
		}
	}
}

func TestCategoryIncludeDoesNotReactivateRetiredPatterns(t *testing.T) {
	tests := []struct {
		category string
		present  string
		retired  []string
	}{
		{
			category: "db",
			present:  "mongodb_uri",
			retired:  []string{"mongodb_srv_connection", "msql_connection_string"},
		},
		{
			category: "cloud",
			present:  "fmfw_2",
			retired: []string{
				"apiflash_2", "apiscience", "caflou", "currentsapi", "datafire",
				"fmfw_1", "hereapi", "lexigram",
				"mixpanel_2", "nethunt_2", "restpackhtmltopdfapi", "simplynoted",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			manager := NewPatternManager()
			if err := manager.LoadPatterns([]string{test.category}, nil); err != nil {
				t.Fatal(err)
			}
			loaded := manager.GetCompiledPatterns()
			if loaded[test.present] == nil {
				t.Fatalf("expected active %s pattern to load", test.present)
			}
			for _, name := range test.retired {
				if loaded[name] != nil {
					t.Errorf("retired pattern %s was reactivated by category include", name)
				}
			}
		})
	}
}

func TestCategoryIncludeStillLoadsOptInPatterns(t *testing.T) {
	for category, names := range map[string][]string{
		"pii": {"email_address", "person_name"},
		"url": {"url_generic", "generic_domain_name"},
	} {
		manager := NewPatternManager()
		if err := manager.LoadPatterns([]string{category}, nil); err != nil {
			t.Fatal(err)
		}
		loaded := manager.GetCompiledPatterns()
		for _, name := range names {
			if loaded[name] == nil {
				t.Errorf("opt-in pattern %s was not loaded for category %s", name, category)
			}
		}
	}
}

func TestPatternRegexesCompile(t *testing.T) {
	for name, cfg := range DefaultPatterns.Patterns {
		if _, err := regexp.Compile(cfg.Regex); err != nil {
			t.Errorf("pattern %q has an invalid regex: %v", name, err)
		}
		for index, raw := range cfg.ExcludeRegexes {
			if _, err := regexp.Compile(raw); err != nil {
				t.Errorf("pattern %q has invalid excluderegex %d: %v", name, index, err)
			}
		}
	}
}

func TestOrderedPatternSnapshotCannotMutateManagerCache(t *testing.T) {
	manager := NewPatternManager()
	first := manager.GetCompiledPatternsOrdered()
	if len(first) == 0 || first[0] == nil {
		t.Fatal("expected at least one compiled pattern")
	}

	original := first[0]
	first[0] = nil

	second := manager.GetCompiledPatternsOrdered()
	if len(second) == 0 || second[0] != original {
		t.Fatal("caller mutation changed the manager's ordered pattern cache")
	}
}
