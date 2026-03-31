package validation

import (
	"regexp"
	"strings"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/utils"
)

type Options struct {
	LocalMode bool
}

type Decision struct {
	Valid      bool
	Confidence float64
}

var (
	secretAssignmentRegex = regexp.MustCompile(`(?i)(api|token|secret|password|key|auth|credential)[^\n\r]{0,20}[:=]`)
	genericContextSignals = []string{
		"apikey", "api_key", "token", "secret", "password", "credential", "auth", "access",
	}
)

func EvaluateCandidate(patternName string, pattern *patterns.CompiledPattern, value, context string, opts Options) Decision {
	if pattern == nil {
		return Decision{Valid: false, Confidence: 0}
	}

	cfg := pattern.Config
	category := strings.ToLower(cfg.Category)
	nameLower := strings.ToLower(patternName)
	valueLower := strings.ToLower(value)
	contextLower := strings.ToLower(context)

	if len(value) < cfg.MinLength {
		return Decision{Valid: false, Confidence: 0}
	}

	if cfg.MaxLength > 0 && len(value) > cfg.MaxLength {
		return Decision{Valid: false, Confidence: 0}
	}

	for _, re := range pattern.CompiledExcludeRegexes {
		if re.MatchString(value) || re.MatchString(context) {
			return Decision{Valid: false, Confidence: 0}
		}
	}

	if utils.IsUUID(value) {
		return Decision{Valid: false, Confidence: 0}
	}

	if category != "url" && (utils.IsLikelyFilePath(value) || utils.IsLikelyContentType(value)) {
		return Decision{Valid: false, Confidence: 0}
	}

	if utils.HasCommonCodePattern(value) && len(value) < 40 {
		return Decision{Valid: false, Confidence: 0}
	}

	if len(cfg.RequiredContextAny) > 0 && !containsAny(contextLower, normalizeTerms(cfg.RequiredContextAny)) {
		return Decision{Valid: false, Confidence: 0}
	}

	score := 0.55

	if shouldUseEntropyValidation(nameLower, cfg) {
		minEntropy := cfg.MinEntropy
		if minEntropy <= 0 {
			minEntropy = 3.5
		}

		entropyMinLength := cfg.EntropyMinLength
		if entropyMinLength <= 0 {
			entropyMinLength = maxInt(12, cfg.MinLength)
		}

		if !utils.IsLikelyRandomSecret(value, minEntropy, entropyMinLength) {
			return Decision{Valid: false, Confidence: 0}
		}

		score += 0.08
	} else if len(value) >= 20 {
		entropy := utils.CalculateEntropy(value)
		if entropy >= 3.7 {
			score += 0.05
		} else if entropy <= 2.2 {
			score -= 0.10
		}
	}

	if secretAssignmentRegex.MatchString(context) {
		score += 0.12
	}

	if containsAny(contextLower, genericContextSignals) {
		score += 0.08
	}

	matchHits := countKeywordHits(valueLower, contextLower, cfg.KeywordMatches)
	if matchHits > 0 {
		score += minFloat(0.12, float64(matchHits)*0.04)
	}

	boostHits := countKeywordHits(valueLower, contextLower, cfg.ContextBoostAny)
	if boostHits > 0 {
		score += minFloat(0.15, float64(boostHits)*0.05)
	}

	excludeHits := countKeywordHits(valueLower, contextLower, cfg.KeywordExcludes)
	if excludeHits > 0 {
		score -= minFloat(0.30, float64(excludeHits)*0.08)
	}

	penaltyHits := countKeywordHits(valueLower, contextLower, cfg.ContextPenaltyAny)
	if penaltyHits > 0 {
		score -= minFloat(0.35, float64(penaltyHits)*0.10)
	}

	if utils.IsLikelyDocumentation(value, context) {
		score -= 0.22
	}

	if utils.IsLikelyTranslationKey(value) || utils.IsLikelyI18nKey(value) {
		score -= 0.18
	}

	if utils.IsLikelyFunctionName(value) || utils.IsJavaScriptFunction(value) {
		score -= 0.15
	}

	if utils.IsJavaScriptConstant(value) {
		score -= 0.10
	}

	if utils.IsInMinifiedCode(value, context) || utils.IsPatternInMinifiedCode(value, context) {
		score -= 0.12
	}

	score += specializedBoost(nameLower, value)

	if opts.LocalMode {
		score += 0.05
	}

	score = clamp(score, 0, 1)
	threshold := 0.50
	if opts.LocalMode {
		threshold = 0.45
	}

	return Decision{Valid: score >= threshold, Confidence: score}
}

func shouldUseEntropyValidation(patternName string, cfg patterns.PatternConfig) bool {
	if cfg.UseEntropy {
		return true
	}

	return strings.Contains(patternName, "password") || strings.Contains(patternName, "session_token")
}

func specializedBoost(patternName, value string) float64 {
	switch {
	case strings.Contains(patternName, "aws") && strings.HasPrefix(value, "AKIA"):
		return 0.22
	case strings.Contains(patternName, "google_api") && strings.HasPrefix(value, "AIza"):
		return 0.22
	case strings.Contains(patternName, "stripe") && (strings.HasPrefix(value, "sk_live_") || strings.HasPrefix(value, "pk_live_")):
		return 0.20
	case strings.Contains(patternName, "jwt") && strings.HasPrefix(value, "eyJ"):
		return 0.15
	case strings.Contains(patternName, "github") && (strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "github_pat_")):
		return 0.18
	default:
		return 0
	}
}

func countKeywordHits(valueLower, contextLower string, keywords []string) int {
	hits := 0
	for _, keyword := range keywords {
		k := strings.ToLower(strings.TrimSpace(keyword))
		if k == "" {
			continue
		}
		if strings.Contains(valueLower, k) || strings.Contains(contextLower, k) {
			hits++
		}
	}
	return hits
}

func containsAny(s string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

func normalizeTerms(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func clamp(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
