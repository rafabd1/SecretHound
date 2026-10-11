package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/pipeline"
	"github.com/rafabd1/SecretHound/networking"
	"github.com/rafabd1/SecretHound/output"
)

type schedulerTestSink struct {
	delay time.Duration
	err   error

	mu       sync.Mutex
	canceled bool
	calls    int
}

func (s *schedulerTestSink) Process(ctx context.Context, _ string, findings []Secret) (pipeline.Result, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			s.mu.Lock()
			s.canceled = true
			s.mu.Unlock()
			return pipeline.Result{Detected: len(findings)}, ctx.Err()
		}
	}

	return pipeline.Result{Detected: len(findings), Emitted: len(findings)}, s.err
}

func (s *schedulerTestSink) state() (calls int, canceled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.canceled
}

func TestSchedulerWaitsForSinkBeforeMarkingURLProcessed(t *testing.T) {
	sink := &schedulerTestSink{delay: 250 * time.Millisecond}
	scheduler, url := newSchedulerTestFixture(t, sink)

	if err := scheduler.Schedule([]string{url}); err != nil {
		t.Fatalf("Schedule() error = %v", err)
	}

	calls, canceled := sink.state()
	if calls != 1 {
		t.Fatalf("sink calls = %d, want 1", calls)
	}
	if canceled {
		t.Fatal("scheduler canceled the sink before it completed")
	}

	stats := scheduler.GetStats()
	if stats.ProcessedURLs != 1 || stats.FailedURLs != 0 || stats.TotalSecrets != 1 {
		t.Fatalf("unexpected scheduler stats: %+v", stats)
	}
}

func TestSchedulerReturnsSinkErrorAndMarksURLFailed(t *testing.T) {
	sinkErr := errors.New("sink failed")
	sink := &schedulerTestSink{err: sinkErr}
	scheduler, url := newSchedulerTestFixture(t, sink)

	err := scheduler.Schedule([]string{url})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Schedule() error = %v, want wrapped sink error", err)
	}

	stats := scheduler.GetStats()
	if stats.ProcessedURLs != 0 || stats.FailedURLs != 1 || stats.TotalSecrets != 0 {
		t.Fatalf("unexpected scheduler stats after sink failure: %+v", stats)
	}
}

func TestSchedulerAccountsForInvalidURLsWithoutHanging(t *testing.T) {
	sink := &schedulerTestSink{}
	scheduler, validURL := newSchedulerTestFixture(t, sink)

	done := make(chan error, 1)
	go func() {
		done <- scheduler.Schedule([]string{validURL, "https://[::1"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Schedule() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		scheduler.Stop()
		t.Fatal("Schedule() did not finish after rejecting an invalid URL")
	}

	stats := scheduler.GetStats()
	if stats.TotalURLs != 2 || stats.ProcessedURLs != 1 || stats.FailedURLs != 1 {
		t.Fatalf("unexpected scheduler stats: %+v", stats)
	}
}

func newSchedulerTestFixture(t *testing.T, sink schedulerSink) (*Scheduler, string) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(`const secret = "q7Vx9Lm2Pk8Rt4Wy6Nz3";`))
	}))
	t.Cleanup(server.Close)

	definitionsPath := filepath.Join(t.TempDir(), "patterns.yaml")
	definitions := []byte(`patterns:
  scheduler_test_secret:
    regex: '(q7Vx9Lm2Pk8Rt4Wy6Nz3)'
    description: Scheduler pipeline test secret
    enabled: true
    category: generic
    minlength: 20
    maxlength: 24
`)
	if err := os.WriteFile(definitionsPath, definitions, 0o600); err != nil {
		t.Fatal(err)
	}

	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadDefinitionsFromFile(definitionsPath); err != nil {
		t.Fatal(err)
	}
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}

	regexManager := NewRegexManager()
	regexManager.SetPatternManager(patternManager)
	logger := output.NewLogger(false, true)
	t.Cleanup(logger.Close)
	processor := NewProcessor(regexManager, logger)

	scheduler, err := NewScheduler(
		networking.NewDomainManager(),
		networking.NewClient(2, 0),
		processor,
		nil,
		logger,
		1,
		true,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	scheduler.sink = sink

	return scheduler, server.URL + "/app.js"
}
