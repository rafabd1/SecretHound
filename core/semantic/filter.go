package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"
)

type queuedCandidate struct {
	candidate Candidate
	key       [32]byte
	response  chan Outcome
}

type Filter struct {
	classifier Classifier
	config     FilterConfig
	requests   chan queuedCandidate
	done       chan struct{}

	stateMu sync.RWMutex
	closed  bool

	cacheMu    sync.Mutex
	cache      map[[32]byte]Prediction
	cacheOrder [][32]byte

	statsMu sync.Mutex
	stats   Stats
}

func NewFilter(classifier Classifier, config FilterConfig) *Filter {
	if config.BatchSize <= 0 {
		config.BatchSize = 16
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 512
	}
	if config.CacheSize <= 0 {
		config.CacheSize = 4096
	}
	if config.BatchWait <= 0 {
		config.BatchWait = 25 * time.Millisecond
	}
	if config.ClassificationTimeout <= 0 {
		config.ClassificationTimeout = 30 * time.Second
	}

	filter := &Filter{
		classifier: classifier,
		config:     config,
		requests:   make(chan queuedCandidate, config.QueueSize),
		done:       make(chan struct{}),
		cache:      make(map[[32]byte]Prediction, config.CacheSize),
		cacheOrder: make([][32]byte, 0, config.CacheSize),
	}
	go filter.run()
	return filter
}

func (f *Filter) Review(ctx context.Context, candidates []Candidate) []Outcome {
	outcomes := make([]Outcome, len(candidates))
	responses := make([]chan Outcome, len(candidates))

	f.stateMu.RLock()
	if f.closed {
		f.stateMu.RUnlock()
		for i := range outcomes {
			outcomes[i] = f.errorOutcome("semantic filter is closed")
			f.recordOutcome(outcomes[i])
		}
		return outcomes
	}

	for i, candidate := range candidates {
		f.incrementReviewed()
		key := candidateKey(candidate)
		if prediction, ok := f.cachedPrediction(key); ok {
			outcomes[i] = f.outcome(prediction, true, "")
			f.incrementCacheHit()
			continue
		}

		response := make(chan Outcome, 1)
		responses[i] = response
		select {
		case f.requests <- queuedCandidate{candidate: candidate, key: key, response: response}:
		case <-ctx.Done():
			outcomes[i] = f.errorOutcome(ctx.Err().Error())
		}
	}
	f.stateMu.RUnlock()

	for i, response := range responses {
		if response == nil {
			f.recordOutcome(outcomes[i])
			continue
		}

		select {
		case outcomes[i] = <-response:
		case <-ctx.Done():
			outcomes[i] = f.errorOutcome(ctx.Err().Error())
		}
		f.recordOutcome(outcomes[i])
	}

	return outcomes
}

func (f *Filter) Close() error {
	f.stateMu.Lock()
	if f.closed {
		f.stateMu.Unlock()
		return nil
	}
	f.closed = true
	close(f.requests)
	f.stateMu.Unlock()

	<-f.done
	return f.classifier.Close()
}

func (f *Filter) Stats() Stats {
	f.statsMu.Lock()
	defer f.statsMu.Unlock()
	return f.stats
}

func (f *Filter) run() {
	defer close(f.done)

	for {
		first, ok := <-f.requests
		if !ok {
			return
		}

		batch := []queuedCandidate{first}
		timer := time.NewTimer(f.config.BatchWait)
		inputClosed := false

	collect:
		for len(batch) < f.config.BatchSize {
			select {
			case request, more := <-f.requests:
				if !more {
					inputClosed = true
					break collect
				}
				batch = append(batch, request)
			case <-timer.C:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		f.processBatch(batch)
		if inputClosed {
			return
		}
	}
}

func (f *Filter) processBatch(batch []queuedCandidate) {
	uniqueCandidates := make([]Candidate, 0, len(batch))
	uniqueKeys := make([][32]byte, 0, len(batch))
	keyIndex := make(map[[32]byte]int, len(batch))
	resolved := make(map[[32]byte]Prediction)
	preCached := make(map[[32]byte]bool)

	for _, request := range batch {
		if prediction, ok := f.cachedPrediction(request.key); ok {
			resolved[request.key] = prediction
			preCached[request.key] = true
			continue
		}
		if _, ok := keyIndex[request.key]; ok {
			continue
		}
		keyIndex[request.key] = len(uniqueCandidates)
		uniqueCandidates = append(uniqueCandidates, request.candidate)
		uniqueKeys = append(uniqueKeys, request.key)
	}

	var classifyErr error
	if len(uniqueCandidates) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), f.config.ClassificationTimeout)
		predictions, err := f.classifier.Classify(ctx, uniqueCandidates)
		cancel()

		if err != nil {
			classifyErr = err
		} else if len(predictions) != len(uniqueCandidates) {
			classifyErr = fmt.Errorf("semantic classifier returned %d predictions for %d candidates", len(predictions), len(uniqueCandidates))
		} else {
			f.statsMu.Lock()
			f.stats.ModelEvaluated += int64(len(uniqueCandidates))
			f.statsMu.Unlock()
			for i, prediction := range predictions {
				prediction = applyPredictionPolicy(uniqueCandidates[i], prediction)
				resolved[uniqueKeys[i]] = prediction
				f.storePrediction(uniqueKeys[i], prediction)
			}
		}
	}

	delivered := make(map[[32]byte]bool, len(resolved))
	for _, request := range batch {
		prediction, ok := resolved[request.key]
		if ok {
			cached := preCached[request.key] || delivered[request.key]
			if cached {
				f.incrementCacheHit()
			}
			delivered[request.key] = true
			request.response <- f.outcome(prediction, cached, "")
			continue
		}
		if classifyErr != nil {
			request.response <- f.errorOutcome(classifyErr.Error())
			continue
		}
		request.response <- f.errorOutcome("semantic classifier did not return a result")
	}
}

func (f *Filter) outcome(prediction Prediction, cached bool, errText string) Outcome {
	return Outcome{
		Prediction: prediction,
		Suppress:   f.config.SuppressLikelyFalsePositives && prediction.Verdict == VerdictLikelyFalsePositive,
		Cached:     cached,
		Error:      errText,
	}
}

func (f *Filter) errorOutcome(message string) Outcome {
	return f.outcome(Prediction{Verdict: VerdictClassificationError}, false, message)
}

func (f *Filter) cachedPrediction(key [32]byte) (Prediction, bool) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()
	prediction, ok := f.cache[key]
	return prediction, ok
}

func (f *Filter) storePrediction(key [32]byte, prediction Prediction) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()

	if _, exists := f.cache[key]; exists {
		f.cache[key] = prediction
		return
	}
	if len(f.cacheOrder) >= f.config.CacheSize {
		oldest := f.cacheOrder[0]
		delete(f.cache, oldest)
		f.cacheOrder = f.cacheOrder[1:]
	}
	f.cache[key] = prediction
	f.cacheOrder = append(f.cacheOrder, key)
}

func (f *Filter) incrementReviewed() {
	f.statsMu.Lock()
	f.stats.Reviewed++
	f.statsMu.Unlock()
}

func (f *Filter) incrementCacheHit() {
	f.statsMu.Lock()
	f.stats.CacheHits++
	f.statsMu.Unlock()
}

func (f *Filter) recordOutcome(outcome Outcome) {
	f.statsMu.Lock()
	defer f.statsMu.Unlock()

	switch outcome.Prediction.Verdict {
	case VerdictLikelyFalsePositive:
		f.stats.LikelyFalsePos++
	case VerdictUncertain:
		f.stats.Uncertain++
	case VerdictNotLikelyFalsePositive:
		f.stats.NotLikelyFalse++
	default:
		f.stats.Errors++
	}
	if outcome.Suppress {
		f.stats.Suppressed++
	}
}

func candidateKey(candidate Candidate) [32]byte {
	hash := sha256.New()
	writeHashString(hash, candidate.Type)
	writeHashString(hash, candidate.Category)
	writeHashString(hash, candidate.Value)
	writeHashString(hash, candidate.Source)
	writeHashString(hash, candidate.Context)
	writeHashString(hash, candidate.Description)
	var numeric [25]byte
	binary.LittleEndian.PutUint64(numeric[:8], uint64(candidate.Line))
	binary.LittleEndian.PutUint64(numeric[8:16], math.Float64bits(candidate.Confidence))
	binary.LittleEndian.PutUint64(numeric[16:24], uint64(candidate.ContextOffset))
	if candidate.HasContextOffset {
		numeric[24] = 1
	}
	_, _ = hash.Write(numeric[:])
	var key [32]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func writeHashString(hash interface{ Write([]byte) (int, error) }, value string) {
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(value))
}

func normalizePrediction(prediction Prediction) Prediction {
	if prediction.Score < 0 {
		prediction.Score = 0
	}
	if prediction.Score > 1 {
		prediction.Score = 1
	}
	switch prediction.Verdict {
	case VerdictLikelyFalsePositive, VerdictNotLikelyFalsePositive, VerdictUncertain:
		return prediction
	default:
		prediction.Verdict = VerdictUncertain
		return prediction
	}
}
