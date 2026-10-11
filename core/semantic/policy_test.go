package semantic

import (
	"reflect"
	"strings"
	"testing"
)

func TestPredictionPolicyPromotesExplicitMismatchDespiteModelVerdict(t *testing.T) {
	t.Parallel()

	candidate := Candidate{
		Type:     "api_key_assignment",
		Category: "generic",
		Value:    "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2",
		Source:   "file:///repo/tests/fixture.json",
	}
	tests := []struct {
		name       string
		prediction Prediction
	}{
		{
			name: "uncertain",
			prediction: Prediction{
				Verdict: VerdictUncertain,
				Score:   0.72,
				Probabilities: map[string]float64{
					string(VerdictNotLikelyFalsePositive): 0.18,
					string(VerdictLikelyFalsePositive):    0.10,
					string(VerdictUncertain):              0.72,
				},
			},
		},
		{
			name: "not likely false positive",
			prediction: Prediction{
				Verdict: VerdictNotLikelyFalsePositive,
				Score:   0.91,
				Probabilities: map[string]float64{
					string(VerdictNotLikelyFalsePositive): 0.91,
					string(VerdictLikelyFalsePositive):    0.03,
					string(VerdictUncertain):              0.06,
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			originalProbabilities := make(map[string]float64, len(test.prediction.Probabilities))
			for label, probability := range test.prediction.Probabilities {
				originalProbabilities[label] = probability
			}

			got := applyPredictionPolicy(candidate, test.prediction)
			if got.Verdict != VerdictLikelyFalsePositive || got.Score != 1 {
				t.Fatalf("explicit evidence did not override %s: %+v", test.prediction.Verdict, got)
			}
			expectedProbabilities := map[string]float64{
				string(VerdictNotLikelyFalsePositive): 0,
				string(VerdictLikelyFalsePositive):    1,
				string(VerdictUncertain):              0,
			}
			if !reflect.DeepEqual(got.Probabilities, expectedProbabilities) {
				t.Fatalf("policy probabilities do not match the promoted verdict: %+v", got.Probabilities)
			}
			if got.Score != got.Probabilities[string(got.Verdict)] {
				t.Fatalf("score does not match promoted verdict probability: %+v", got)
			}
			if !reflect.DeepEqual(test.prediction.Probabilities, originalProbabilities) {
				t.Fatalf("policy mutated classifier probabilities: %+v", test.prediction.Probabilities)
			}
		})
	}
}

func TestPredictionPolicyDoesNotPromoteWithoutExplicitMismatch(t *testing.T) {
	t.Parallel()

	candidate := Candidate{
		Type:     "api_key_assignment",
		Category: "generic",
		Value:    "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2",
		Source:   "file:///repo/src/config.js",
		Context:  `const api_key = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"`,
	}
	for _, verdict := range []Verdict{VerdictUncertain, VerdictNotLikelyFalsePositive} {
		prediction := Prediction{Verdict: verdict, Score: 0.77}
		if got := applyPredictionPolicy(candidate, prediction); !reflect.DeepEqual(got, prediction) {
			t.Fatalf("%s was overridden without explicit evidence: got %+v, want %+v", verdict, got, prediction)
		}
	}

	modelFalsePositive := Prediction{
		Verdict: VerdictLikelyFalsePositive,
		Score:   0.93,
		Probabilities: map[string]float64{
			string(VerdictLikelyFalsePositive): 0.93,
			string(VerdictUncertain):           0.05,
		},
	}
	got := applyPredictionPolicy(candidate, modelFalsePositive)
	if got.Verdict != VerdictUncertain || got.Score != 0.05 {
		t.Fatalf("model-only false-positive verdict bypassed the evidence gate: %+v", got)
	}
}

func TestPredictionPolicyPromotesEachExplicitEvidenceClass(t *testing.T) {
	t.Parallel()

	value := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	tests := []struct {
		name      string
		candidate Candidate
	}{
		{
			name:      "non-production path",
			candidate: Candidate{Type: "api_key_assignment", Value: value, Source: "file:///repo/docs/config.md"},
		},
		{
			name: "marker",
			candidate: Candidate{
				Type: "api_key_assignment", Value: value,
				Context: `const example_api_key = "` + value + `"`,
			},
		},
		{
			name: "mismatch phrase",
			candidate: Candidate{
				Type: "api_key_assignment", Value: value,
				Context: `const api_key = "` + value + `"; // Shell command, not a secret.`,
			},
		},
		{
			name:      "reserved PII",
			candidate: Candidate{Type: "ipv4_address", Category: "pii", Value: "192.0.2.44"},
		},
		{
			name:      "non-person name",
			candidate: Candidate{Type: "person_name", Category: "pii", Value: "Engineering Manager"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := applyPredictionPolicy(test.candidate, Prediction{Verdict: VerdictUncertain, Score: 0.72})
			if got.Verdict != VerdictLikelyFalsePositive || got.Score != 1 {
				t.Fatalf("explicit evidence class was not promoted: %+v", got)
			}
		})
	}
}

func TestObviousNonProductionSourceRecognizesExplicitTestAndFixturePaths(t *testing.T) {
	t.Parallel()

	sources := []string{
		"file:///repo/pkg/testdata/config.json",
		"file:///repo/__fixtures__/users.ts",
		"file:///repo/src/auth.test.js",
		"file:///repo/src/auth.spec.js",
		"file:///repo/src/auth.spec.ts",
		"file:///repo/src/auth.test.ts",
		"file:///repo/src/auth.spec.tsx",
		"file:///repo/src/auth.test.tsx",
		"file:///repo/src/auth.spec.jsx",
		"file:///repo/src/auth.test.jsx",
		"file:///repo/core/auth_test.go",
		`C:\repo\dev\filesTest\cases.json`,
	}
	for _, source := range sources {
		source := source
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			if !isObviousNonProductionSource(source) {
				t.Fatalf("explicit test or fixture source was not recognized: %s", source)
			}
		})
	}
}

func TestObviousNonProductionSourceDoesNotTrustPathSubstrings(t *testing.T) {
	t.Parallel()

	sources := []string{
		"file:///repo/src/contestdata/config.js",
		"file:///repo/src/latest.js",
		"file:///repo/src/fixtures-service/client.ts",
		"file:///repo/src/workflow.spec.ts.backup",
	}
	for _, source := range sources {
		source := source
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			if isObviousNonProductionSource(source) {
				t.Fatalf("ambiguous production source was treated as test evidence: %s", source)
			}
		})
	}
}

func TestObviousNonPersonNameRecognizesSystemLabels(t *testing.T) {
	t.Parallel()

	values := []string{
		"Runtime Config",
		"API Gateway",
		"Customer Platform",
		"Admin Portal",
		"Deployment Workflow",
	}
	for _, value := range values {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			candidate := Candidate{Type: "person_name", Category: "pii", Value: value}
			if !isObviousNonPersonName(candidate) {
				t.Fatalf("clear system label was not recognized: %s", value)
			}
		})
	}
}

func TestObviousNonPersonNamePreservesPlausiblePeople(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"Marina Costa", "Workflow Jones", "Portal Silva"} {
		candidate := Candidate{Type: "person_name", Category: "pii", Value: value}
		if isObviousNonPersonName(candidate) {
			t.Fatalf("plausible person name was treated as a system label: %s", value)
		}
	}
}

func TestSemanticMarkerInProductionContextIsExplicitFalsePositiveEvidence(t *testing.T) {
	t.Parallel()

	candidate := Candidate{
		Type:     "api_key_assignment",
		Category: "generic",
		Value:    "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2",
		Context:  `const example_api_key = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"`,
		Source:   "file:///repo/src/config.js",
	}
	if !hasObviousSemanticMismatch(candidate) {
		t.Fatal("explicit example marker in nearby context was not accepted as false-positive evidence")
	}

	candidate.Context = `const api_key = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"`
	if hasObviousSemanticMismatch(candidate) {
		t.Fatal("ordinary production assignment was treated as obvious false-positive evidence")
	}

	candidate.Context = `const example_mode = false; const api_key = "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"`
	if hasObviousSemanticMismatch(candidate) {
		t.Fatal("an unrelated marker authorized false-positive suppression")
	}
}

func TestSemanticMarkerUsesTheExactFindingOccurrence(t *testing.T) {
	t.Parallel()

	value := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	context := `const example_api_key = "` + value + `"; const api_key = "` + value + `"`
	candidate := Candidate{
		Type:             "api_key_assignment",
		Category:         "generic",
		Value:            value,
		Context:          context,
		Source:           "file:///repo/src/config.js",
		ContextOffset:    strings.LastIndex(context, value),
		HasContextOffset: true,
	}
	if hasObviousSemanticMismatch(candidate) {
		t.Fatal("marker from another occurrence authorized suppression")
	}

	candidate.ContextOffset = strings.Index(context, value)
	if !hasObviousSemanticMismatch(candidate) {
		t.Fatal("marker attached to the exact finding was ignored")
	}
}

func TestMismatchPhraseInAttachedTrailingCommentIsExplicitEvidence(t *testing.T) {
	t.Parallel()

	value := "npm-install-production"
	context := `const app_key = "` + value + `"; // Shell command name, not a secret.`
	candidate := Candidate{
		Type:             "api_key_assignment",
		Category:         "generic",
		Value:            value,
		Context:          context,
		Source:           "file:///repo/src/config.js",
		ContextOffset:    strings.Index(context, value),
		HasContextOffset: true,
	}
	if !hasObviousSemanticMismatch(candidate) {
		t.Fatal("attached trailing comment was not accepted as explicit false-positive evidence")
	}

	context = `const app_key = "` + value + `"; const note = "not a secret"`
	candidate.Context = context
	candidate.ContextOffset = strings.Index(context, value)
	if hasObviousSemanticMismatch(candidate) {
		t.Fatal("a later statement was treated as evidence for the finding")
	}
}
