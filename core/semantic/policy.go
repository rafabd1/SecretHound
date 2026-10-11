package semantic

import (
	"net/netip"
	"regexp"
	"strings"
)

var semanticMarkerPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(changeme|dummy|example|fake|fixture|mock|placeholder|redacted|replace_me|sample)(?:$|[^a-z0-9])`)

var semanticMismatchPhrases = []string{
	"asset path",
	"command name",
	"file path",
	"not a secret",
	"package name",
	"public domain",
	"public hostname",
	"public url",
	"shell command",
}

var semanticNonProductionPathParts = map[string]struct{}{
	"__fixtures__":  {},
	"doc":           {},
	"docs":          {},
	"documentation": {},
	"example":       {},
	"examples":      {},
	"filestest":     {},
	"fixture":       {},
	"fixtures":      {},
	"mock":          {},
	"mocks":         {},
	"sample":        {},
	"samples":       {},
	"test":          {},
	"testdata":      {},
	"tests":         {},
}

var semanticNonProductionFileSuffixes = []string{
	".spec.cjs",
	".spec.js",
	".spec.jsx",
	".spec.mjs",
	".spec.ts",
	".spec.tsx",
	".test.cjs",
	".test.js",
	".test.jsx",
	".test.mjs",
	".test.ts",
	".test.tsx",
	"_test.go",
}

var semanticNonPersonNameSuffixes = map[string]struct{}{
	"administrator": {},
	"committee":     {},
	"config":        {},
	"department":    {},
	"division":      {},
	"gateway":       {},
	"group":         {},
	"manager":       {},
	"notes":         {},
	"office":        {},
	"platform":      {},
	"portal":        {},
	"service":       {},
	"team":          {},
	"workflow":      {},
}

func applyPredictionPolicy(candidate Candidate, prediction Prediction) Prediction {
	prediction = normalizePrediction(prediction)
	if hasObviousSemanticMismatch(candidate) {
		if prediction.Verdict == VerdictLikelyFalsePositive {
			return prediction
		}
		return explicitMismatchPrediction()
	}
	if prediction.Verdict != VerdictLikelyFalsePositive {
		return prediction
	}

	prediction.Verdict = VerdictUncertain
	if score, ok := prediction.Probabilities[string(VerdictUncertain)]; ok {
		prediction.Score = score
	} else {
		prediction.Score = 0
	}
	return prediction
}

func explicitMismatchPrediction() Prediction {
	return Prediction{
		Verdict: VerdictLikelyFalsePositive,
		Score:   1,
		Probabilities: map[string]float64{
			string(VerdictNotLikelyFalsePositive): 0,
			string(VerdictLikelyFalsePositive):    1,
			string(VerdictUncertain):              0,
		},
	}
}

func hasObviousSemanticMismatch(candidate Candidate) bool {
	if isReservedPIIExample(candidate) {
		return true
	}
	if isObviousNonPersonName(candidate) {
		return true
	}
	if semanticMarkerPattern.MatchString(strings.ToLower(candidate.Value)) {
		return true
	}

	context := strings.ToLower(relatedCandidateContext(candidate))
	if context == "" {
		return isObviousNonProductionSource(candidate.Source)
	}
	if semanticMarkerPattern.MatchString(context) {
		return true
	}
	for _, phrase := range semanticMismatchPhrases {
		if strings.Contains(context, phrase) {
			return true
		}
	}

	return isObviousNonProductionSource(candidate.Source)
}

func relatedCandidateContext(candidate Candidate) string {
	context := candidate.Context
	value := candidate.Value
	if context == "" || value == "" {
		return ""
	}

	offset := -1
	if candidate.HasContextOffset && candidate.ContextOffset >= 0 &&
		candidate.ContextOffset+len(value) <= len(context) &&
		context[candidate.ContextOffset:candidate.ContextOffset+len(value)] == value {
		offset = candidate.ContextOffset
	} else {
		first := strings.Index(context, value)
		if first < 0 || strings.Index(context[first+len(value):], value) >= 0 {
			return ""
		}
		offset = first
	}

	start := offset
	for start > 0 && !isSemanticStatementBoundary(context[start-1]) {
		start--
	}
	end := offset + len(value)
	for end < len(context) && !isSemanticStatementBoundary(context[end]) {
		end++
	}
	if end < len(context) && context[end] == ';' {
		commentStart := end + 1
		for commentStart < len(context) && (context[commentStart] == ' ' || context[commentStart] == '\t') {
			commentStart++
		}
		if strings.HasPrefix(context[commentStart:], "//") ||
			strings.HasPrefix(context[commentStart:], "#") ||
			strings.HasPrefix(context[commentStart:], "/*") {
			end = commentStart
			for end < len(context) && context[end] != '\n' && context[end] != '\r' {
				end++
			}
		}
	}
	return context[start:end]
}

func isSemanticStatementBoundary(character byte) bool {
	switch character {
	case '\n', '\r', ';', ',', '{', '}':
		return true
	default:
		return false
	}
}

func isObviousNonProductionSource(source string) bool {
	normalized := strings.NewReplacer("\\", "/").Replace(strings.ToLower(strings.TrimSpace(source)))
	if index := strings.IndexAny(normalized, "?#"); index >= 0 {
		normalized = normalized[:index]
	}

	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if _, ok := semanticNonProductionPathParts[part]; ok {
			return true
		}
	}

	fileName := parts[len(parts)-1]
	for _, suffix := range semanticNonProductionFileSuffixes {
		if strings.HasSuffix(fileName, suffix) {
			return true
		}
	}
	return false
}

func isObviousNonPersonName(candidate Candidate) bool {
	if strings.ToLower(strings.TrimSpace(candidate.Type)) != "person_name" {
		return false
	}

	words := strings.Fields(strings.ToLower(strings.TrimSpace(candidate.Value)))
	if len(words) < 2 {
		return false
	}
	_, ok := semanticNonPersonNameSuffixes[words[len(words)-1]]
	return ok
}

func isReservedPIIExample(candidate Candidate) bool {
	if ReviewModeForCategory(candidate.Category) != ReviewModePII {
		return false
	}

	value := strings.ToLower(strings.TrimSpace(candidate.Value))
	switch strings.ToLower(candidate.Type) {
	case "ipv4_address":
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return false
		}
		return address.IsLoopback() || address.IsUnspecified() ||
			prefixContains("192.0.2.0/24", address) ||
			prefixContains("198.51.100.0/24", address) ||
			prefixContains("203.0.113.0/24", address)
	case "ipv6_address":
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is6() {
			return false
		}
		return address.IsLoopback() || address.IsUnspecified() || prefixContains("2001:db8::/32", address)
	case "mac_address":
		compact := alphanumeric(value)
		return compact == "000000000000" || compact == "ffffffffffff"
	case "phone_number":
		digits := decimalDigits(value)
		if len(digits) < 10 {
			return false
		}
		national := digits[len(digits)-10:]
		return national[3:6] == "555" && national[6:] >= "0100" && national[6:] <= "0199"
	case "us_zip_code":
		return value == "00000" || value == "00000-0000"
	default:
		return false
	}
}

func prefixContains(rawPrefix string, address netip.Addr) bool {
	prefix, err := netip.ParsePrefix(rawPrefix)
	return err == nil && prefix.Contains(address)
}

func alphanumeric(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func decimalDigits(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= '0' && character <= '9' {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
