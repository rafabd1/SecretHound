package semantic

import (
	"context"
	"strings"
	"time"
)

type ReviewMode string

const (
	ReviewModeSecret ReviewMode = "secret"
	ReviewModePII    ReviewMode = "pii"
	ReviewModeBypass ReviewMode = "bypass"
)

func ReviewModeForCategory(category string) ReviewMode {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "url", "bash":
		return ReviewModeBypass
	case "pii":
		return ReviewModePII
	default:
		return ReviewModeSecret
	}
}

type Verdict string

const (
	VerdictNotLikelyFalsePositive Verdict = "not_likely_false_positive"
	VerdictLikelyFalsePositive    Verdict = "likely_false_positive"
	VerdictUncertain              Verdict = "uncertain"
	VerdictClassificationError    Verdict = "classification_error"
)

type Candidate struct {
	Type             string  `json:"detector_type"`
	Category         string  `json:"category,omitempty"`
	Value            string  `json:"value"`
	Source           string  `json:"source"`
	Line             int     `json:"line,omitempty"`
	Context          string  `json:"context,omitempty"`
	Description      string  `json:"description,omitempty"`
	Confidence       float64 `json:"heuristic_confidence,omitempty"`
	ContextOffset    int     `json:"-"`
	HasContextOffset bool    `json:"-"`
}

type Prediction struct {
	Verdict       Verdict            `json:"verdict"`
	Score         float64            `json:"score"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

type Outcome struct {
	Prediction Prediction
	Suppress   bool
	Cached     bool
	Error      string
}

type Classifier interface {
	Classify(context.Context, []Candidate) ([]Prediction, error)
	Close() error
}

type FilterConfig struct {
	BatchSize                    int
	QueueSize                    int
	CacheSize                    int
	BatchWait                    time.Duration
	ClassificationTimeout        time.Duration
	SuppressLikelyFalsePositives bool
}

type Stats struct {
	Reviewed       int64
	ModelEvaluated int64
	CacheHits      int64
	LikelyFalsePos int64
	Uncertain      int64
	NotLikelyFalse int64
	Errors         int64
	Suppressed     int64
}
