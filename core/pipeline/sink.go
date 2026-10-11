package pipeline

import (
	"context"
	"errors"

	"github.com/rafabd1/SecretHound/core/finding"
	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/semantic"
	"github.com/rafabd1/SecretHound/output"
)

type Sink struct {
	patternManager    *patterns.PatternManager
	writer            *output.Writer
	logger            *output.Logger
	semanticFilter    *semantic.Filter
	forceInfoFindings bool
}

type Result struct {
	Detected   int
	Emitted    int
	Suppressed int
	Collapsed  int
}

func NewSink(patternManager *patterns.PatternManager, writer *output.Writer, logger *output.Logger, semanticFilter *semantic.Filter, forceInfoFindings bool) *Sink {
	return &Sink{
		patternManager:    patternManager,
		writer:            writer,
		logger:            logger,
		semanticFilter:    semanticFilter,
		forceInfoFindings: forceInfoFindings,
	}
}

func (s *Sink) Process(ctx context.Context, sourceForGrouping string, findings []finding.Finding) (Result, error) {
	result := Result{Detected: len(findings)}
	if len(findings) == 0 {
		return result, nil
	}

	processed := ResolvePatternCollisions(s.patternManager, findings)
	result.Collapsed = len(findings) - len(processed)
	if s.semanticFilter != nil {
		processed = s.applySemanticFilter(ctx, processed, &result)
	}
	result.Emitted = len(processed)

	s.logFindings(processed)
	return result, s.writeFindings(sourceForGrouping, processed)
}

func ResolvePatternCollisions(patternManager *patterns.PatternManager, findings []finding.Finding) []finding.Finding {
	type collisionKey struct {
		source string
		line   int
		offset int
		value  string
	}

	groups := make(map[collisionKey][]int, len(findings))
	for index, item := range findings {
		key := collisionKey{source: item.URL, line: item.Line, offset: item.ByteOffset, value: item.Value}
		groups[key] = append(groups[key], index)
	}

	drop := make([]bool, len(findings))
	for _, indexes := range groups {
		if len(indexes) < 2 {
			continue
		}

		priorities := make(map[int]int, len(indexes))
		types := make(map[string]struct{}, len(indexes))
		maxPriority := 0
		minPriority := 0
		for position, index := range indexes {
			item := findings[index]
			types[item.Type] = struct{}{}
			priority := 0
			if patternManager != nil {
				if config, ok := patternManager.GetPatternConfig(item.Type); ok {
					priority = config.CollisionPriority
				}
			}
			priorities[index] = priority
			if position == 0 || priority > maxPriority {
				maxPriority = priority
			}
			if position == 0 || priority < minPriority {
				minPriority = priority
			}
		}
		if len(types) < 2 || maxPriority == minPriority {
			continue
		}
		for _, index := range indexes {
			if priorities[index] < maxPriority {
				drop[index] = true
			}
		}
	}

	resolved := make([]finding.Finding, 0, len(findings))
	for index, item := range findings {
		if !drop[index] {
			resolved = append(resolved, item)
		}
	}
	return resolved
}

func (s *Sink) applySemanticFilter(ctx context.Context, findings []finding.Finding, result *Result) []finding.Finding {
	candidates := make([]semantic.Candidate, 0, len(findings))
	indexes := make([]int, 0, len(findings))
	for i, item := range findings {
		category := ""
		if config, ok := s.patternManager.GetPatternConfig(item.Type); ok {
			category = config.Category
		}
		if semantic.ReviewModeForCategory(category) == semantic.ReviewModeBypass {
			continue
		}
		indexes = append(indexes, i)
		candidates = append(candidates, semantic.Candidate{
			Type:             item.Type,
			Category:         category,
			Value:            item.Value,
			Source:           item.URL,
			Line:             item.Line,
			Context:          item.Context,
			Description:      item.Description,
			Confidence:       item.Confidence,
			ContextOffset:    item.ContextOffset,
			HasContextOffset: item.HasContextOffset,
		})
	}

	if len(candidates) == 0 {
		return findings
	}
	outcomes := s.semanticFilter.Review(ctx, candidates)
	outcomesByIndex := make(map[int]semantic.Outcome, len(indexes))
	for i, index := range indexes {
		outcomesByIndex[index] = outcomes[i]
	}
	kept := make([]finding.Finding, 0, len(findings))
	for i, item := range findings {
		outcome, reviewed := outcomesByIndex[i]
		if !reviewed {
			kept = append(kept, item)
			continue
		}
		item.FilterStatus = string(outcome.Prediction.Verdict)
		item.FilterScore = outcome.Prediction.Score
		if outcome.Prediction.Verdict == semantic.VerdictLikelyFalsePositive {
			item.ReviewPriority = "low"
		}
		if outcome.Suppress {
			result.Suppressed++
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

func (s *Sink) logFindings(findings []finding.Finding) {
	type groupedFinding struct {
		finding finding.Finding
		count   int
	}

	grouped := make(map[string]*groupedFinding, len(findings))
	order := make([]string, 0, len(findings))
	for _, item := range findings {
		key := item.Type + "\x00" + item.Value + "\x00" + item.URL + "\x00" + item.FilterStatus
		if existing, ok := grouped[key]; ok {
			existing.count++
			continue
		}
		grouped[key] = &groupedFinding{finding: item, count: 1}
		order = append(order, key)
	}

	for _, key := range order {
		entry := grouped[key]
		risk := patterns.ResolveFindingRisk(entry.finding.Type, s.patternManager)
		s.logger.SecretFoundWithCountReview(
			entry.finding.Type,
			entry.finding.Value,
			entry.finding.URL,
			entry.count,
			string(risk),
			s.forceInfoFindings,
			entry.finding.FilterStatus,
			entry.finding.ReviewPriority,
		)
	}
}

func (s *Sink) writeFindings(sourceForGrouping string, findings []finding.Finding) error {
	if s.writer == nil {
		return nil
	}

	var writeErrors []error
	for _, item := range findings {
		risk := patterns.ResolveFindingRisk(item.Type, s.patternManager)
		err := s.writer.WriteFinding(sourceForGrouping, output.SecretFindingData{
			Type:           item.Type,
			Risk:           string(risk),
			Value:          item.Value,
			SourceURL:      item.URL,
			Line:           item.Line,
			ByteOffset:     item.ByteOffset,
			Context:        contextSlice(item.Context),
			Occurrences:    1,
			Description:    item.Description,
			Confidence:     item.Confidence,
			ReviewPriority: item.ReviewPriority,
			FilterStatus:   item.FilterStatus,
			FilterScore:    item.FilterScore,
		})
		if err != nil {
			writeErrors = append(writeErrors, err)
		}
	}
	return errors.Join(writeErrors...)
}

func contextSlice(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}
