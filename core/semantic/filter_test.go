package semantic

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClassifier struct {
	mu          sync.Mutex
	calls       int
	batchSizes  []int
	closeCalled bool
	fail        bool
	block       bool
}

func (f *fakeClassifier) Classify(ctx context.Context, candidates []Candidate) ([]Prediction, error) {
	f.mu.Lock()
	f.calls++
	f.batchSizes = append(f.batchSizes, len(candidates))
	f.mu.Unlock()

	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.fail {
		return nil, errors.New("classification failed")
	}

	predictions := make([]Prediction, len(candidates))
	for i, candidate := range candidates {
		switch candidate.Value {
		case "placeholder-value":
			predictions[i] = Prediction{Verdict: VerdictLikelyFalsePositive, Score: 0.98}
		case "uncertain":
			predictions[i] = Prediction{Verdict: VerdictUncertain, Score: 0.51}
		default:
			predictions[i] = Prediction{Verdict: VerdictNotLikelyFalsePositive, Score: 0.95}
		}
	}
	return predictions, nil
}

func (f *fakeClassifier) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalled = true
	return nil
}

func TestFilterSuppressesOnlyLikelyFalsePositives(t *testing.T) {
	classifier := &fakeClassifier{}
	filter := NewFilter(classifier, FilterConfig{
		BatchSize:                    8,
		QueueSize:                    8,
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcomes := filter.Review(context.Background(), []Candidate{
		{Type: "test", Value: "placeholder-value"},
		{Type: "test", Value: "uncertain"},
		{Type: "test", Value: "real-looking"},
	})

	if !outcomes[0].Suppress {
		t.Fatal("likely false positive was not suppressed")
	}
	if outcomes[1].Suppress || outcomes[2].Suppress {
		t.Fatal("uncertain or retained finding was suppressed")
	}
	if outcomes[1].Prediction.Verdict != VerdictUncertain {
		t.Fatalf("unexpected uncertain verdict: %s", outcomes[1].Prediction.Verdict)
	}

	stats := filter.Stats()
	if stats.Reviewed != 3 || stats.Suppressed != 1 || stats.Uncertain != 1 || stats.NotLikelyFalse != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestFilterMarksWithoutSuppressing(t *testing.T) {
	filter := NewFilter(&fakeClassifier{}, FilterConfig{
		BatchSize:             2,
		QueueSize:             2,
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	defer filter.Close()

	outcomes := filter.Review(context.Background(), []Candidate{{Value: "placeholder-value"}})
	if outcomes[0].Suppress {
		t.Fatal("mark-only mode suppressed a finding")
	}
	if outcomes[0].Prediction.Verdict != VerdictLikelyFalsePositive {
		t.Fatalf("unexpected verdict: %s", outcomes[0].Prediction.Verdict)
	}
}

func TestFilterAllowsExplicitPlaceholderEvidence(t *testing.T) {
	filter := NewFilter(&fakeClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcome := filter.Review(context.Background(), []Candidate{{
		Type:    "google_api_key",
		Value:   "placeholder-value",
		Source:  "file:///repo/generated/config.js",
		Context: "const publicGoogleBrowserKey = credential",
	}})[0]
	if !outcome.Suppress || outcome.Prediction.Verdict != VerdictLikelyFalsePositive {
		t.Fatalf("explicit placeholder was not suppressible: %+v", outcome)
	}
}

func TestFilterDoesNotTrustGeneratedOrSubstringPathAsFalsePositiveEvidence(t *testing.T) {
	filter := NewFilter(&alwaysFalsePositiveClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	for _, source := range []string{"file:///repo/generated/runtime_config.js", "file:///repo/contest/latest/config.js"} {
		outcome := filter.Review(context.Background(), []Candidate{
			{Type: "google_api_key", Value: "AIzaSyA7mQ9xV2nR5tY8uP3kL6cB1hF4jW0zE7Q", Source: source, Context: "const publicGoogleBrowserKey = value"},
		})[0]
		if outcome.Suppress || outcome.Prediction.Verdict != VerdictUncertain {
			t.Fatalf("weak source path authorized suppression for %s: %+v", source, outcome)
		}
	}
}

func TestFilterAllowsClearNonProductionSourceEvidence(t *testing.T) {
	filter := NewFilter(&alwaysFalsePositiveClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	for _, source := range []string{"file:///repo/tests/fixture.json", "file:///repo/docs/example.md"} {
		outcome := filter.Review(context.Background(), []Candidate{{
			Type: "api_key_assignment", Value: "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2", Source: source,
		}})[0]
		if !outcome.Suppress || outcome.Prediction.Verdict != VerdictLikelyFalsePositive {
			t.Fatalf("clear non-production path was ignored for %s: %+v", source, outcome)
		}
	}
}

func TestFilterAllowsObviousContextMismatch(t *testing.T) {
	filter := NewFilter(&alwaysFalsePositiveClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcome := filter.Review(context.Background(), []Candidate{{
		Type:    "api_key_assignment",
		Value:   "assets.runtime.chunk.js",
		Context: `const api_secret = "assets.runtime.chunk.js" // Asset path, not a secret.`,
	}})[0]
	if !outcome.Suppress || outcome.Prediction.Verdict != VerdictLikelyFalsePositive {
		t.Fatalf("obvious semantic mismatch was not suppressible: %+v", outcome)
	}
}

func TestFilterAllowsClearNonPersonNameValue(t *testing.T) {
	filter := NewFilter(&alwaysFalsePositiveClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	role := filter.Review(context.Background(), []Candidate{{
		Type:     "person_name",
		Category: "pii",
		Value:    "Engineering Manager",
		Source:   "file:///repo/production/customer.json",
		Context:  `employee_name = "Engineering Manager"`,
	}})[0]
	if !role.Suppress || role.Prediction.Verdict != VerdictLikelyFalsePositive {
		t.Fatalf("clear non-person name value was not suppressible: %+v", role)
	}

	person := filter.Review(context.Background(), []Candidate{{
		Type:     "person_name",
		Category: "pii",
		Value:    "Marina Costa",
		Source:   "file:///repo/production/customer.json",
		Context:  `customer_name = "Marina Costa"`,
	}})[0]
	if person.Suppress || person.Prediction.Verdict != VerdictUncertain {
		t.Fatalf("plausible person name was not protected: %+v", person)
	}
}

type alwaysFalsePositiveClassifier struct{}

func (*alwaysFalsePositiveClassifier) Classify(_ context.Context, candidates []Candidate) ([]Prediction, error) {
	predictions := make([]Prediction, len(candidates))
	for i := range predictions {
		predictions[i] = Prediction{
			Verdict: VerdictLikelyFalsePositive,
			Score:   0.99,
			Probabilities: map[string]float64{
				string(VerdictNotLikelyFalsePositive): 0.005,
				string(VerdictLikelyFalsePositive):    0.99,
				string(VerdictUncertain):              0.005,
			},
		}
	}
	return predictions, nil
}

func (*alwaysFalsePositiveClassifier) Close() error { return nil }

type nonFalsePositiveClassifier struct{}

func (*nonFalsePositiveClassifier) Classify(_ context.Context, candidates []Candidate) ([]Prediction, error) {
	predictions := make([]Prediction, len(candidates))
	for i := range candidates {
		if i%2 == 0 {
			predictions[i] = Prediction{Verdict: VerdictUncertain, Score: 0.74}
		} else {
			predictions[i] = Prediction{Verdict: VerdictNotLikelyFalsePositive, Score: 0.88}
		}
	}
	return predictions, nil
}

func (*nonFalsePositiveClassifier) Close() error { return nil }

func TestFilterSuppressesExplicitMismatchDespiteModelVerdict(t *testing.T) {
	filter := NewFilter(&nonFalsePositiveClassifier{}, FilterConfig{
		BatchSize:                    2,
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcomes := filter.Review(context.Background(), []Candidate{
		{
			Type:   "api_key_assignment",
			Value:  "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2",
			Source: "file:///repo/tests/fixture.json",
		},
		{
			Type:     "person_name",
			Category: "pii",
			Value:    "Engineering Manager",
			Source:   "file:///repo/src/customer.json",
		},
	})
	for i, outcome := range outcomes {
		if outcome.Prediction.Verdict != VerdictLikelyFalsePositive || !outcome.Suppress {
			t.Fatalf("explicit mismatch %d was not promoted and suppressed: %+v", i, outcome)
		}
		if outcome.Prediction.Score != 1 || outcome.Prediction.Probabilities[string(VerdictLikelyFalsePositive)] != 1 {
			t.Fatalf("explicit mismatch %d has inconsistent policy confidence: %+v", i, outcome)
		}
	}

	stats := filter.Stats()
	if stats.LikelyFalsePos != 2 || stats.Suppressed != 2 || stats.Uncertain != 0 || stats.NotLikelyFalse != 0 {
		t.Fatalf("promoted outcomes were not counted consistently: %+v", stats)
	}
}

func TestFilterKeepsFindingsWhenClassificationFails(t *testing.T) {
	filter := NewFilter(&fakeClassifier{fail: true}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcome := filter.Review(context.Background(), []Candidate{{Value: "candidate"}})[0]
	if outcome.Suppress {
		t.Fatal("classification error suppressed a finding")
	}
	if outcome.Prediction.Verdict != VerdictClassificationError {
		t.Fatalf("unexpected verdict: %s", outcome.Prediction.Verdict)
	}
}

func TestFilterCachesCompletedPredictions(t *testing.T) {
	classifier := &fakeClassifier{}
	filter := NewFilter(classifier, FilterConfig{
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	defer filter.Close()

	candidate := Candidate{Type: "token", Value: "same", Source: "file.js", Context: "ctx"}
	filter.Review(context.Background(), []Candidate{candidate})
	second := filter.Review(context.Background(), []Candidate{candidate})[0]
	if !second.Cached {
		t.Fatal("second prediction was not served from cache")
	}
	if classifier.calls != 1 {
		t.Fatalf("classifier called %d times, expected 1", classifier.calls)
	}
	if filter.Stats().CacheHits != 1 {
		t.Fatalf("unexpected cache stats: %+v", filter.Stats())
	}
}

func TestFilterKeepsCachedPredictionWhenAnotherCandidateFails(t *testing.T) {
	filter := NewFilter(&fakeClassifier{fail: true}, FilterConfig{
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	defer filter.Close()

	cachedCandidate := Candidate{Type: "token", Value: "cached", Source: "cached.js"}
	freshCandidate := Candidate{Type: "token", Value: "fresh", Source: "fresh.js"}
	cachedKey := candidateKey(cachedCandidate)
	freshKey := candidateKey(freshCandidate)
	filter.storePrediction(cachedKey, Prediction{Verdict: VerdictNotLikelyFalsePositive, Score: 0.94})

	cachedResponse := make(chan Outcome, 1)
	freshResponse := make(chan Outcome, 1)
	filter.processBatch([]queuedCandidate{
		{candidate: cachedCandidate, key: cachedKey, response: cachedResponse},
		{candidate: freshCandidate, key: freshKey, response: freshResponse},
	})

	cachedOutcome := <-cachedResponse
	if cachedOutcome.Error != "" || !cachedOutcome.Cached || cachedOutcome.Prediction.Verdict != VerdictNotLikelyFalsePositive {
		t.Fatalf("cached prediction was degraded by batch error: %+v", cachedOutcome)
	}
	freshOutcome := <-freshResponse
	if freshOutcome.Error == "" || freshOutcome.Suppress || freshOutcome.Prediction.Verdict != VerdictClassificationError {
		t.Fatalf("fresh candidate did not preserve classification error: %+v", freshOutcome)
	}
}

func TestFilterDeduplicatesCandidatesWithinBatch(t *testing.T) {
	classifier := &fakeClassifier{}
	filter := NewFilter(classifier, FilterConfig{
		BatchSize:             4,
		QueueSize:             4,
		BatchWait:             time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	defer filter.Close()

	candidate := Candidate{Type: "token", Value: "same", Source: "file.js", Context: "ctx"}
	outcomes := filter.Review(context.Background(), []Candidate{candidate, candidate})
	if outcomes[0].Cached || !outcomes[1].Cached {
		t.Fatalf("unexpected cache markers: %+v", outcomes)
	}
	if classifier.calls != 1 || classifier.batchSizes[0] != 1 {
		t.Fatalf("duplicate reached classifier: calls=%d batches=%v", classifier.calls, classifier.batchSizes)
	}
	if filter.Stats().CacheHits != 1 {
		t.Fatalf("unexpected cache stats: %+v", filter.Stats())
	}
}

func TestFilterDoesNotDeduplicateDistinctContextOccurrences(t *testing.T) {
	filter := NewFilter(&alwaysFalsePositiveClassifier{}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        time.Second,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	value := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"
	contextText := `const example_api_key = "` + value + `"; const api_key = "` + value + `"`
	first := Candidate{
		Type:             "api_key_assignment",
		Value:            value,
		Context:          contextText,
		ContextOffset:    strings.Index(contextText, value),
		HasContextOffset: true,
	}
	second := first
	second.ContextOffset = strings.LastIndex(contextText, value)

	outcomes := filter.Review(context.Background(), []Candidate{first, second})
	if !outcomes[0].Suppress || outcomes[0].Prediction.Verdict != VerdictLikelyFalsePositive {
		t.Fatalf("example occurrence was not suppressible: %+v", outcomes[0])
	}
	if outcomes[1].Suppress || outcomes[1].Prediction.Verdict != VerdictUncertain {
		t.Fatalf("production occurrence reused the example prediction: %+v", outcomes[1])
	}
}

func TestFilterBatchesCandidates(t *testing.T) {
	classifier := &fakeClassifier{}
	filter := NewFilter(classifier, FilterConfig{
		BatchSize:             4,
		QueueSize:             16,
		BatchWait:             20 * time.Millisecond,
		ClassificationTimeout: time.Second,
	})
	defer filter.Close()

	candidates := make([]Candidate, 9)
	for i := range candidates {
		candidates[i] = Candidate{Type: "token", Value: string(rune('a' + i))}
	}
	filter.Review(context.Background(), candidates)

	classifier.mu.Lock()
	defer classifier.mu.Unlock()
	if classifier.calls != 3 {
		t.Fatalf("classifier called %d times, expected 3 batches", classifier.calls)
	}
	if classifier.batchSizes[0] != 4 || classifier.batchSizes[1] != 4 || classifier.batchSizes[2] != 1 {
		t.Fatalf("unexpected batch sizes: %v", classifier.batchSizes)
	}
}

func TestFilterTimeoutKeepsFinding(t *testing.T) {
	filter := NewFilter(&fakeClassifier{block: true}, FilterConfig{
		BatchWait:                    time.Millisecond,
		ClassificationTimeout:        10 * time.Millisecond,
		SuppressLikelyFalsePositives: true,
	})
	defer filter.Close()

	outcome := filter.Review(context.Background(), []Candidate{{Value: "candidate"}})[0]
	if outcome.Suppress || outcome.Prediction.Verdict != VerdictClassificationError {
		t.Fatalf("timeout did not preserve finding: %+v", outcome)
	}
}
