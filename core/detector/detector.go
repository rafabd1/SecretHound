package detector

import (
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
	ProcessingErrors int
}

func NewDetector(patternManager *patterns.PatternManager, logger *output.Logger, config Config) *Detector {
	if config.ContextSize == 0 {
		config.ContextSize = 100
	}

	if config.MinConfidence == 0 {
		config.MinConfidence = 0.5
	}

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

	d.patternManager.SetLocalMode(d.config.LocalFileMode)

	patterns := d.patternManager.GetCompiledPatterns()

	d.logger.Debug("Using %d regex patterns for detection", len(patterns))

	if len(patterns) == 0 {
		fallback := NewFallbackDetector()
		secrets := fallback.DetectWithFallback(content, url)

		if len(secrets) > 0 {
			d.logger.Warning("Using fallback detection mode - limited patterns available")

			d.mu.Lock()
			d.stats.SecretsFound += len(secrets)
			d.mu.Unlock()

			return secrets, nil
		}
	}

	var secrets []secret.Secret

	for _, pattern := range patterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) == 0 {
				continue
			}

			value := match[0]
			if len(match) > 1 && match[1] != "" {
				value = match[1]
			}

			ctx := secret.ExtractContext(content, value, d.config.ContextSize)

			line := utils.FindLineNumber(content, value)

			valid, confidence := d.validateSecret(pattern.Name, value, ctx)

			if valid && confidence >= d.config.MinConfidence {
				s := secret.NewSecret(pattern.Name, value, ctx, url, line)
				s.Confidence = confidence
				s.Description = pattern.Description

				secrets = append(secrets, s)
			}
		}
	}

	if len(secrets) == 0 && d.stats.ProcessingErrors > 5 {
		fallback := NewFallbackDetector()
		fallbackSecrets := fallback.DetectWithFallback(content, url)

		if len(fallbackSecrets) > 0 {
			d.logger.Warning("Detection errors detected - using fallback patterns")
			secrets = fallbackSecrets
		}
	}

	d.mu.Lock()
	d.stats.SecretsFound += len(secrets)
	d.mu.Unlock()

	return secrets, nil
}

/*
Validates a potential secret and returns validity and confidence score
*/
func (d *Detector) validateSecret(
	patternName, value, context string,
) (bool, float64) {
	patterns := d.patternManager.GetCompiledPatterns()
	pattern, exists := patterns[patternName]
	if !exists {
		return false, 0
	}

	config := pattern.Config

	if len(value) < config.MinLength {
		return false, 0
	}

	if config.MaxLength > 0 && len(value) > config.MaxLength {
		return false, 0
	}

	decision := validation.EvaluateCandidate(patternName, pattern, value, context, validation.Options{
		LocalMode: d.config.LocalFileMode,
	})
	return decision.Valid, decision.Confidence
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
