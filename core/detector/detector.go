package detector

import (
	"fmt"
	"sync"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/secret"
	"github.com/rafabd1/SecretHound/core/validation"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

type Config struct {
	LocalFileMode     bool
	MinConfidence     float64
	ContextSize       int
	AllowTestExamples bool
}

type Detector struct {
	patternManager *patterns.PatternManager
	logger         *output.Logger
	config         Config
	mu             sync.Mutex
	stats          Stats
}

type Stats struct {
	ContentProcessed int
	SecretsFound     int
}

func NewDetector(patternManager *patterns.PatternManager, logger *output.Logger, config Config) *Detector {
	config = normalizeConfig(config)

	return &Detector{
		patternManager: patternManager,
		logger:         logger,
		config:         config,
		stats:          Stats{},
	}
}

func (d *Detector) DetectSecrets(content, url string) ([]secret.Secret, error) {
	d.mu.Lock()
	d.stats.ContentProcessed++
	d.mu.Unlock()

	if d.patternManager != nil && d.logger != nil {
		d.logger.Debug("Using %d regex patterns for detection", d.patternManager.GetPatternCount())
	}

	secrets, err := ScanContent(d.patternManager, d.config, content, url)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.stats.SecretsFound += len(secrets)
	d.mu.Unlock()

	return secrets, nil
}

// ScanContent is the shared detection path for local files and remote content.
// Source-specific transport code must not apply different regex or length rules.
func ScanContent(patternManager *patterns.PatternManager, config Config, content, url string) ([]secret.Secret, error) {
	if patternManager == nil {
		return nil, fmt.Errorf("pattern manager is nil")
	}

	config = normalizeConfig(config)
	compiled := patternManager.GetCompiledPatternsOrdered()
	if len(compiled) == 0 {
		return nil, fmt.Errorf("no compiled patterns loaded; check pattern configuration")
	}

	var secrets []secret.Secret
	for _, pattern := range compiled {
		matches := pattern.Regex.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			start, end, ok := preferredMatchBounds(match)
			if !ok {
				continue
			}

			value := validation.NormalizeCandidateWithBounds(
				pattern.Name,
				pattern,
				content[start:end],
				precedingByte(content, start),
				followingByte(content, end),
			)
			if value == "" {
				continue
			}
			end = start + len(value)

			ctx, matchOffset := secret.ExtractContextAtWithMatchOffset(content, start, end, config.ContextSize)
			contextStart := start - matchOffset
			contextEnd := contextStart + len(ctx)
			decision := validation.EvaluateCandidate(pattern.Name, pattern, value, ctx, validation.Options{
				LocalMode:                   config.LocalFileMode,
				MatchOffset:                 matchOffset,
				HasMatchOffset:              true,
				ContextStartsAtLineBoundary: startsAtLineBoundary(content, contextStart),
				ContextEndsAtLineBoundary:   endsAtLineBoundary(content, contextEnd),
			})
			if !decision.Valid || decision.Confidence < config.MinConfidence {
				continue
			}

			finding := secret.NewSecret(pattern.Name, value, ctx, url, utils.FindLineNumberAtOffset(content, start))
			finding.ByteOffset = start
			finding.ContextOffset = matchOffset
			finding.HasContextOffset = true
			finding.Confidence = decision.Confidence
			finding.Description = pattern.Description
			secrets = append(secrets, finding)
		}
	}

	return secrets, nil
}

func startsAtLineBoundary(content string, offset int) bool {
	return offset == 0 || offset > 0 && offset <= len(content) && content[offset-1] == '\n'
}

func endsAtLineBoundary(content string, offset int) bool {
	if offset == len(content) {
		return true
	}
	if offset < 0 || offset >= len(content) {
		return false
	}
	return content[offset] == '\n' ||
		content[offset] == '\r' && offset+1 < len(content) && content[offset+1] == '\n'
}

func normalizeConfig(config Config) Config {
	if config.ContextSize == 0 {
		config.ContextSize = 100
	}
	if config.MinConfidence == 0 {
		config.MinConfidence = 0.5
	}
	return config
}

func preferredMatchBounds(match []int) (int, int, bool) {
	if len(match) < 2 || match[0] < 0 || match[1] < 0 {
		return 0, 0, false
	}

	start, end := match[0], match[1]
	if len(match) >= 4 && match[2] >= 0 && match[3] >= 0 {
		start, end = match[2], match[3]
	}
	return start, end, true
}

func precedingByte(content string, start int) byte {
	if start <= 0 || start > len(content) {
		return 0
	}
	return content[start-1]
}

func followingByte(content string, end int) byte {
	if end < 0 || end >= len(content) {
		return 0
	}
	return content[end]
}

func (d *Detector) GetStats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.stats
}

func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats = Stats{}
}

func (d *Detector) SetConfig(config Config) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.config = config
}
