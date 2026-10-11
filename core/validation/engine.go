package validation

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/utils"
	"golang.org/x/net/publicsuffix"
)

type Options struct {
	LocalMode                   bool
	MatchOffset                 int
	HasMatchOffset              bool
	ContextStartsAtLineBoundary bool
	ContextEndsAtLineBoundary   bool
}

type Decision struct {
	Valid      bool
	Confidence float64
}

const defaultMaxCandidateLength = 4096

var (
	secretAssignmentRegex                  = regexp.MustCompile(`(?i)(api|token|secret|password|key|auth|credential)[^\n\r]{0,20}[:=]`)
	looseProviderRegex                     = regexp.MustCompile(`^(?:\(\?i:)?\(\?:((?:\\.|[A-Za-z0-9_.-])+)\)\.\{0,40\}(?:\))?`)
	directProviderSeparatedCredentialRegex = regexp.MustCompile(`(?i)^[._-](?:api[._-]?(?:key|token|secret)|access[._-]?token|auth[._-]?(?:key|token|secret)|app[._-]?secret|secret|token|password|credential|admin[._-]?key|private[._-]?key|key)["']?\s*[:=]\s*["']?\s*$`)
	directProviderCamelCredentialRegex     = regexp.MustCompile(`^(?:ApiKey|ApiToken|ApiSecret|APIKey|APIToken|APISecret|AccessToken|AuthKey|AuthToken|AuthSecret|Secret|Token|Password|Credential|AdminKey|PrivateKey|Key)["']?\s*[:=]\s*["']?\s*$`)
	directProviderQuotedCredentialRegex    = regexp.MustCompile(`(?i)^\[\s*["'](?:api[._ -]?(?:key|token|secret)|access[._ -]?token|auth[._ -]?(?:key|token|secret)|secret|token|password|credential|admin[._ -]?key|private[._ -]?key|key)["']\s*\]\s*[:=]\s*["']?\s*$`)
	nestedCredentialLabelRegex             = regexp.MustCompile(`(?i)^\s*["']?(?:api[._ -]?(?:key|token|secret)|access[._ -]?token|auth[._ -]?(?:key|token|secret)|secret|token|password|credential|admin[._ -]?key|private[._ -]?key|key)["']?\s*[:=]\s*["']?\s*$`)
	yamlCredentialNameRegex                = regexp.MustCompile(`(?i)^(?:api[._ -]?(?:key|token|secret)|access[._ -]?token|auth[._ -]?(?:key|token|secret)|secret|token|password|credential|admin[._ -]?key|private[._ -]?key|key)$`)
	credentialReferenceRegex               = regexp.MustCompile(`(?i)^(?:process\.env|import\.meta\.env|deno\.env|config|settings|secrets?)\.[A-Za-z_][A-Za-z0-9_]*$`)
	secp256k1Order                         = mustBigInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	genericContextSignals                  = []string{
		"apikey", "api_key", "token", "secret", "password", "credential", "auth", "access",
	}
)

func EvaluateCandidate(patternName string, pattern *patterns.CompiledPattern, value, context string, opts Options) Decision {
	if pattern == nil {
		return Decision{Valid: false, Confidence: 0}
	}
	value = NormalizeCandidate(patternName, pattern, value)

	cfg := pattern.Config
	category := strings.ToLower(cfg.Category)
	nameLower := strings.ToLower(patternName)
	valueLower := strings.ToLower(value)
	nearbyContext := candidateScopedContext(value, context, opts)
	nearbyContextLower := strings.ToLower(nearbyContext)

	if len(value) < cfg.MinLength {
		return Decision{Valid: false, Confidence: 0}
	}

	if cfg.MaxLength > 0 && len(value) > cfg.MaxLength {
		return Decision{Valid: false, Confidence: 0}
	}
	if cfg.MaxLength == 0 && len(value) > defaultMaxCandidateLength {
		return Decision{Valid: false, Confidence: 0}
	}

	for _, re := range pattern.CompiledExcludeRegexes {
		if re.MatchString(value) || re.MatchString(nearbyContext) {
			return Decision{Valid: false, Confidence: 0}
		}
	}

	provider := looseProviderName(cfg.Regex)
	if provider == "" && len(cfg.RequiredContextAny) > 0 && !containsRequiredContextTerm(nearbyContext, cfg.RequiredContextAny) {
		return Decision{Valid: false, Confidence: 0}
	}
	if provider != "" {
		if !hasLooseProviderCredentialContext(pattern.Regex, provider, value, context, opts) ||
			isObviousCredentialPlaceholder(value) {
			return Decision{Valid: false, Confidence: 0}
		}
	}
	if nameLower == "web3_private_key" && !isValidWeb3PrivateKey(value) {
		return Decision{Valid: false, Confidence: 0}
	}
	if isCredentialURIType(nameLower) && !isValidCredentialURI(nameLower, value) {
		return Decision{Valid: false, Confidence: 0}
	}
	if nameLower == "mssql_connection_string" && !isValidMSSQLConnectionString(value) {
		return Decision{Valid: false, Confidence: 0}
	}
	if nameLower == "credit_card_number" && !isValidPaymentCard(value) {
		return Decision{Valid: false, Confidence: 0}
	}
	if nameLower == "jwt_token" && !isValidJWT(value) {
		return Decision{Valid: false, Confidence: 0}
	}
	if nameLower == "basic_auth" && !isValidBasicAuth(value) {
		return Decision{Valid: false, Confidence: 0}
	}

	if category == "url" {
		return evaluateURLCandidate(nameLower, value)
	}
	if category == "bash" {
		return Decision{Valid: true, Confidence: 0.80}
	}

	if category == "pii" {
		if !isValidPIIShape(nameLower, valueLower) ||
			isObviousPIIPlaceholder(nameLower, valueLower) ||
			(strings.Contains(nameLower, "email") && isPlaceholderEmail(valueLower)) {
			return Decision{Valid: false, Confidence: 0}
		}
		return evaluatePIICandidate(cfg, valueLower, nearbyContextLower, opts)
	}
	if isObviousSecretPlaceholder(nameLower, value) {
		return Decision{Valid: false, Confidence: 0}
	}

	if category != "url" && !allowsPathCharacters(nameLower) &&
		(utils.IsLikelyFilePath(value) || utils.IsLikelyContentType(value)) {
		return Decision{Valid: false, Confidence: 0}
	}
	if credentialReferenceRegex.MatchString(value) {
		return Decision{Valid: false, Confidence: 0}
	}

	if utils.HasCommonCodePattern(value) && len(value) < 40 {
		return Decision{Valid: false, Confidence: 0}
	}

	if strings.Contains(nameLower, "email") && isPlaceholderEmail(valueLower) {
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

	if secretAssignmentRegex.MatchString(nearbyContext) {
		score += 0.12
	}

	if containsAny(nearbyContextLower, genericContextSignals) {
		score += 0.08
	}

	matchHits := countKeywordHits(valueLower, nearbyContextLower, cfg.KeywordMatches)
	if matchHits > 0 {
		score += minFloat(0.12, float64(matchHits)*0.04)
	}

	boostHits := countKeywordHits(valueLower, nearbyContextLower, cfg.ContextBoostAny)
	if boostHits > 0 {
		score += minFloat(0.15, float64(boostHits)*0.05)
	}

	excludeHits := countKeywordHits(valueLower, nearbyContextLower, cfg.KeywordExcludes)
	if excludeHits > 0 {
		score -= minFloat(0.30, float64(excludeHits)*0.08)
	}

	penaltyHits := countKeywordHits(valueLower, nearbyContextLower, cfg.ContextPenaltyAny)
	if penaltyHits > 0 {
		score -= minFloat(0.35, float64(penaltyHits)*0.10)
	}

	if utils.IsLikelyDocumentation(value, nearbyContext) {
		score -= 0.22
	}

	if !isKnownStructuredCredential(nameLower, value) &&
		(utils.IsLikelyTranslationKey(value) || utils.IsLikelyI18nKey(value)) {
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

func candidateScopedContext(value, context string, opts Options) string {
	if value == "" || context == "" {
		return ""
	}

	offset := -1
	if opts.HasMatchOffset {
		if opts.MatchOffset < 0 || opts.MatchOffset+len(value) > len(context) ||
			context[opts.MatchOffset:opts.MatchOffset+len(value)] != value {
			return ""
		}
		offset = opts.MatchOffset
	} else {
		offset = strings.Index(context, value)
		if offset < 0 {
			return context
		}
		if strings.Index(context[offset+len(value):], value) >= 0 {
			return context
		}
	}

	start := offset
	for start > 0 && !isCandidateContextBoundary(context[start-1]) {
		start--
	}
	parentBoundary := start
	for parentBoundary > 0 && isASCIIWhitespace(context[parentBoundary-1]) {
		parentBoundary--
	}
	if parentBoundary > 0 && context[parentBoundary-1] == '{' {
		if parentStart, ok := parentObjectLabelStart(context, parentBoundary-1); ok {
			start = parentStart
		}
	}
	end := offset + len(value)
	for end < len(context) && !isCandidateContextBoundary(context[end]) {
		end++
	}
	return context[start:end]
}

func parentObjectLabelStart(context string, openingBrace int) (int, bool) {
	if openingBrace <= 0 || openingBrace >= len(context) || context[openingBrace] != '{' {
		return 0, false
	}

	end := openingBrace
	for end > 0 && isASCIIWhitespace(context[end-1]) {
		end--
	}
	if end == 0 || (context[end-1] != ':' && context[end-1] != '=') {
		return 0, false
	}
	end--
	for end > 0 && isASCIIWhitespace(context[end-1]) {
		end--
	}
	if end == 0 {
		return 0, false
	}

	if quote := context[end-1]; quote == '\'' || quote == '"' {
		start := end - 1
		for start > 0 && context[start-1] != quote && context[start-1] != '\n' && context[start-1] != '\r' {
			start--
		}
		if start == 0 || context[start-1] != quote || start == end-1 {
			return 0, false
		}
		return start - 1, true
	}

	start := end
	for start > 0 && isObjectLabelCharacter(context[start-1]) {
		start--
	}
	return start, start < end
}

func isCandidateContextBoundary(character byte) bool {
	switch character {
	case '\n', '\r', ';', ',', '{', '}':
		return true
	default:
		return false
	}
}

func containsRequiredContextTerm(context string, terms []string) bool {
	for _, rawTerm := range terms {
		term := strings.TrimSpace(rawTerm)
		if term == "" {
			continue
		}
		for start := 0; start <= len(context)-len(term); start++ {
			if !equalFoldASCIIAt(context, start, term) {
				continue
			}
			end := start + len(term)
			if isContextTermStart(context, start) && isContextTermEnd(context, end) {
				return true
			}
		}
	}
	return false
}

func equalFoldASCIIAt(value string, start int, term string) bool {
	if start < 0 || start+len(term) > len(value) {
		return false
	}
	for index := 0; index < len(term); index++ {
		left := value[start+index]
		right := term[index]
		if left >= 128 || right >= 128 {
			return false
		}
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func isContextTermStart(context string, start int) bool {
	if start == 0 || !isASCIIAlphaNumeric(context[start-1]) {
		return true
	}
	return isASCIIUpper(context[start]) && isASCIILower(context[start-1])
}

func isContextTermEnd(context string, end int) bool {
	if end == len(context) || !isASCIIAlphaNumeric(context[end]) {
		return true
	}
	return end > 0 && isASCIIUpper(context[end]) &&
		(isASCIILower(context[end-1]) || end+1 < len(context) && isASCIILower(context[end+1]))
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func isASCIIUpper(character byte) bool {
	return character >= 'A' && character <= 'Z'
}

func isASCIILower(character byte) bool {
	return character >= 'a' && character <= 'z'
}

func isASCIIWhitespace(character byte) bool {
	switch character {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func isObjectLabelCharacter(character byte) bool {
	return isASCIIAlphaNumeric(character) || character == '_' || character == '-' || character == '.'
}

func allowsPathCharacters(patternName string) bool {
	switch patternName {
	case "discord_webhook", "mssql_connection_string", "sentry_org_auth_token", "slack_webhook":
		return true
	default:
		return false
	}
}

func looseProviderName(expression string) string {
	match := looseProviderRegex.FindStringSubmatch(expression)
	if len(match) != 2 {
		return ""
	}
	return strings.NewReplacer(`\.`, ".", `\-`, "-", `\+`, "+").Replace(match[1])
}

func hasLooseProviderCredentialContext(expression *regexp.Regexp, provider, value, context string, opts Options) bool {
	if expression == nil {
		return false
	}
	for _, match := range expression.FindAllStringSubmatchIndex(context, -1) {
		if len(match) < 4 || match[0] < 0 || match[2] < 0 || match[3] < 0 {
			continue
		}
		if opts.HasMatchOffset && match[2] != opts.MatchOffset {
			continue
		}
		if context[match[2]:match[3]] != value || !hasProviderBoundaryAt(context, match[0], len(provider)) {
			continue
		}
		prefix := context[match[0]:match[2]]
		if strings.ContainsAny(prefix, "{\r\n") {
			if hasNestedProviderCredentialPrefix(prefix, provider) ||
				hasYAMLProviderCredentialContext(context, match[0], match[2], match[3], provider, opts) {
				return true
			}
			continue
		}
		if hasDirectProviderCredentialPrefix(prefix, provider) {
			return true
		}
	}
	return false
}

func hasNestedProviderCredentialPrefix(prefix, provider string) bool {
	if len(prefix) < len(provider) || !strings.EqualFold(prefix[:len(provider)], provider) {
		return false
	}
	remainder := prefix[len(provider):]
	brace := strings.IndexByte(remainder, '{')
	if brace < 0 {
		return false
	}

	header := strings.TrimSpace(remainder[:brace])
	if len(header) > 0 && (header[0] == '\'' || header[0] == '"') {
		header = strings.TrimSpace(header[1:])
	}
	if header != ":" && header != "=" {
		return false
	}
	return hasDirectObjectCredentialLabel(remainder[brace+1:])
}

func hasDirectObjectCredentialLabel(objectPrefix string) bool {
	depth := 1
	fieldStart := 0
	quote := byte(0)
	escaped := false

	for index := 0; index < len(objectPrefix); index++ {
		character := objectPrefix[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}

		switch character {
		case '\'', '"', '`':
			quote = character
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 1 {
				return false
			}
		case ',':
			if depth == 1 {
				fieldStart = index + 1
			}
		}
	}

	return depth == 1 && nestedCredentialLabelRegex.MatchString(objectPrefix[fieldStart:])
}

func hasDirectProviderCredentialPrefix(prefix, provider string) bool {
	if len(prefix) < len(provider) || !strings.EqualFold(prefix[:len(provider)], provider) {
		return false
	}
	remainder := prefix[len(provider):]
	return directProviderSeparatedCredentialRegex.MatchString(remainder) ||
		directProviderCamelCredentialRegex.MatchString(remainder) ||
		directProviderQuotedCredentialRegex.MatchString(remainder)
}

func hasYAMLProviderCredentialContext(context string, providerStart, valueStart, valueEnd int, provider string, opts Options) bool {
	providerEnd := providerStart + len(provider)
	if providerStart < 0 || providerEnd > valueStart || valueStart > valueEnd || valueEnd > len(context) ||
		!strings.EqualFold(context[providerStart:providerEnd], provider) {
		return false
	}

	lineStart := strings.LastIndexByte(context[:providerStart], '\n') + 1
	if lineStart == 0 && !opts.ContextStartsAtLineBoundary {
		return false
	}
	headerPrefix := context[lineStart:providerStart]
	headerQuote := byte(0)
	if len(headerPrefix) > 0 {
		last := headerPrefix[len(headerPrefix)-1]
		if last == '\'' || last == '"' {
			headerQuote = last
			headerPrefix = headerPrefix[:len(headerPrefix)-1]
		}
	}
	if !isSpacesOnly(headerPrefix) {
		return false
	}
	headerIndent := len(headerPrefix)

	headerEndRelative := strings.IndexByte(context[providerEnd:valueStart], '\n')
	if headerEndRelative < 0 {
		return false
	}
	headerEnd := providerEnd + headerEndRelative
	headerSuffix := context[providerEnd:headerEnd]
	if strings.HasSuffix(headerSuffix, "\r") {
		headerSuffix = headerSuffix[:len(headerSuffix)-1]
	}
	expectedHeaderSuffix := ":"
	if headerQuote != 0 {
		expectedHeaderSuffix = string(headerQuote) + ":"
	}
	if headerSuffix != expectedHeaderSuffix {
		return false
	}

	childStart := headerEnd + 1
	for childStart < valueStart {
		lineEndRelative := strings.IndexByte(context[childStart:valueStart], '\n')
		if lineEndRelative < 0 {
			break
		}
		lineEnd := childStart + lineEndRelative
		line := context[childStart:lineEnd]
		if strings.HasSuffix(line, "\r") {
			line = line[:len(line)-1]
		}
		if !isSpacesOnly(line) {
			return false
		}
		childStart = lineEnd + 1
	}

	linePrefix := context[childStart:valueStart]
	indent := 0
	for indent < len(linePrefix) && linePrefix[indent] == ' ' {
		indent++
	}
	if indent <= headerIndent {
		return false
	}
	valueQuote, valid := parseYAMLCredentialLabelPrefix(linePrefix[indent:])
	if !valid {
		return false
	}

	lineEndRelative := strings.IndexByte(context[valueEnd:], '\n')
	lineEnd := len(context)
	if lineEndRelative >= 0 {
		lineEnd = valueEnd + lineEndRelative
	} else if !opts.ContextEndsAtLineBoundary {
		return false
	}
	lineSuffix := context[valueEnd:lineEnd]
	if strings.HasSuffix(lineSuffix, "\r") {
		lineSuffix = lineSuffix[:len(lineSuffix)-1]
	}
	if valueQuote != 0 {
		if len(lineSuffix) == 0 || lineSuffix[0] != valueQuote {
			return false
		}
		lineSuffix = lineSuffix[1:]
	}
	return isSpacesOnly(lineSuffix)
}

func parseYAMLCredentialLabelPrefix(prefix string) (byte, bool) {
	colon := strings.IndexByte(prefix, ':')
	if colon <= 0 {
		return 0, false
	}
	label := prefix[:colon]
	if label[0] == '\'' || label[0] == '"' {
		if len(label) < 2 || label[len(label)-1] != label[0] {
			return 0, false
		}
		label = label[1 : len(label)-1]
	} else if label[len(label)-1] == '\'' || label[len(label)-1] == '"' {
		return 0, false
	}
	if !yamlCredentialNameRegex.MatchString(label) {
		return 0, false
	}

	valuePrefix := prefix[colon+1:]
	spaces := 0
	for spaces < len(valuePrefix) && valuePrefix[spaces] == ' ' {
		spaces++
	}
	valuePrefix = valuePrefix[spaces:]
	if valuePrefix == "" {
		return 0, true
	}
	if len(valuePrefix) == 1 && (valuePrefix[0] == '\'' || valuePrefix[0] == '"') {
		return valuePrefix[0], true
	}
	return 0, false
}

func isSpacesOnly(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != ' ' {
			return false
		}
	}
	return true
}

func hasProviderBoundaryAt(text string, start, providerLength int) bool {
	if start < 0 || providerLength <= 0 || start+providerLength > len(text) {
		return false
	}
	if start > 0 {
		previous, size := utf8.DecodeLastRuneInString(text[:start])
		if isUnicodeIdentifierRune(previous, size) {
			return false
		}
	}
	end := start + providerLength
	if end == len(text) {
		return true
	}
	next, size := utf8.DecodeRuneInString(text[end:])
	if !isUnicodeIdentifierRune(next, size) {
		return true
	}
	return next >= 'A' && next <= 'Z'
}

func isUnicodeIdentifierRune(character rune, size int) bool {
	if character == utf8.RuneError && size == 1 {
		return true
	}
	return unicode.IsLetter(character) || unicode.IsNumber(character) || unicode.IsMark(character)
}

func isValidWeb3PrivateKey(value string) bool {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if len(raw) != 64 {
		return false
	}
	scalar, ok := new(big.Int).SetString(raw, 16)
	return ok && scalar.Sign() > 0 && scalar.Cmp(secp256k1Order) < 0
}

func mustBigInt(value string) *big.Int {
	parsed, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid static integer")
	}
	return parsed
}

func isCredentialURIType(patternName string) bool {
	switch patternName {
	case "mongodb_uri", "mysql_connection_string", "postgresql_connection_string", "redis_url":
		return true
	default:
		return false
	}
}

func isValidCredentialURI(patternName, value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User == nil {
		return false
	}
	if _, present := parsed.User.Password(); !present {
		return false
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch patternName {
	case "mongodb_uri":
		return scheme == "mongodb" || scheme == "mongodb+srv"
	case "mysql_connection_string":
		return scheme == "mysql"
	case "postgresql_connection_string":
		return scheme == "postgres" || scheme == "postgresql"
	case "redis_url":
		return scheme == "redis" || scheme == "rediss"
	default:
		return false
	}
}

func isValidMSSQLConnectionString(value string) bool {
	var hasServer, hasUser, hasPassword bool
	for _, part := range splitConnectionString(value) {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		key := strings.Join(strings.Fields(strings.ToLower(keyValue[0])), " ")
		fieldValue := strings.TrimSpace(keyValue[1])
		if len(fieldValue) >= 2 && strings.HasPrefix(fieldValue, "{") && strings.HasSuffix(fieldValue, "}") {
			fieldValue = strings.TrimSpace(fieldValue[1 : len(fieldValue)-1])
		}
		if fieldValue == "" {
			continue
		}
		switch key {
		case "server", "data source", "address", "addr", "network address":
			hasServer = true
		case "user id", "uid", "user":
			hasUser = true
		case "password", "pwd":
			hasPassword = true
		}
	}
	return hasServer && hasUser && hasPassword
}

func splitConnectionString(value string) []string {
	var parts []string
	start := 0
	braces := 0
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case ';':
			if braces == 0 {
				parts = append(parts, value[start:index])
				start = index + 1
			}
		}
	}
	if start < len(value) {
		parts = append(parts, value[start:])
	}
	return parts
}

func evaluatePIICandidate(cfg patterns.PatternConfig, valueLower, contextLower string, opts Options) Decision {
	score := 0.70

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
	if utils.IsLikelyDocumentation(valueLower, contextLower) {
		score -= 0.12
	}
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

func evaluateURLCandidate(patternName, value string) Decision {
	// URL extraction is driven by its regex. Secret-oriented entropy, documentation,
	// translation-key, and code-shape checks reject valid URLs by construction. The
	// category still applies syntax and pattern-specific endpoint checks.
	switch patternName {
	case "url_generic":
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" {
			return Decision{Valid: false, Confidence: 0}
		}
		if schemeRequiresHost(parsed.Scheme) && parsed.Hostname() == "" {
			return Decision{Valid: false, Confidence: 0}
		}
		if parsed.Hostname() == "" && parsed.Path == "" {
			return Decision{Valid: false, Confidence: 0}
		}
	case "generic_domain_name":
		if !hasICANNTLD(value) {
			return Decision{Valid: false, Confidence: 0}
		}
	case "url_path":
		if !strings.HasPrefix(value, "/") {
			return Decision{Valid: false, Confidence: 0}
		}
		if _, err := url.ParseRequestURI(value); err != nil {
			return Decision{Valid: false, Confidence: 0}
		}
	}

	return Decision{Valid: true, Confidence: 0.80}
}

func schemeRequiresHost(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ftp", "ftps", "sftp", "ssh", "git", "ws", "wss",
		"ldap", "ldaps", "redis", "rediss", "mongodb", "mongodb+srv", "mysql",
		"mariadb", "amqp", "amqps":
		return true
	default:
		return false
	}
}

func hasICANNTLD(value string) bool {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	lastDot := strings.LastIndexByte(domain, '.')
	if lastDot < 0 || lastDot == len(domain)-1 {
		return false
	}
	tld := domain[lastDot+1:]
	_, icann := publicsuffix.PublicSuffix("probe." + tld)
	return icann
}

// NormalizeCandidate removes prose delimiters that are not part of an
// absolute URI. It leaves balanced delimiters, such as an IPv6 host or a path
// with parentheses, intact.
func NormalizeCandidate(patternName string, pattern *patterns.CompiledPattern, value string) string {
	return NormalizeCandidateWithBounds(patternName, pattern, value, 0, 0)
}

// NormalizeCandidateWithLeading removes delimiters that wrap a URL in
// surrounding prose or Markdown. leading is the byte immediately before value.
func NormalizeCandidateWithLeading(patternName string, pattern *patterns.CompiledPattern, value string, leading byte) string {
	return NormalizeCandidateWithBounds(patternName, pattern, value, leading, 0)
}

// NormalizeCandidateWithBounds uses bytes outside the regex match to separate
// URL punctuation from surrounding prose without changing a URL at end of input.
func NormalizeCandidateWithBounds(patternName string, pattern *patterns.CompiledPattern, value string, leading, trailing byte) string {
	if pattern == nil || !strings.EqualFold(strings.TrimSpace(pattern.Config.Category), "url") ||
		!strings.EqualFold(strings.TrimSpace(patternName), "url_generic") {
		return value
	}

	end := len(value)
	parentheses := 0
	brackets := 0
	braces := 0
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '(':
			parentheses++
		case ')':
			if parentheses == 0 && (hasTrailingSyntax(value[index+1:]) ||
				(leading == '(' && index == len(value)-1)) {
				end = index
				index = len(value)
				continue
			}
			parentheses--
		case '[':
			brackets++
		case ']':
			if brackets == 0 && hasTrailingSyntax(value[index+1:]) {
				end = index
				index = len(value)
				continue
			}
			brackets--
		case '{':
			braces++
		case '}':
			if braces == 0 && hasTrailingSyntax(value[index+1:]) {
				end = index
				index = len(value)
				continue
			}
			braces--
		}
	}

	normalized := value[:end]
	if trailing != ' ' && trailing != '\t' && trailing != '\r' && trailing != '\n' {
		return normalized
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return normalized
	}
	return strings.TrimRight(normalized, ".,;")
}

func hasTrailingSyntax(suffix string) bool {
	return suffix != "" && strings.ContainsRune(".,;!})]", rune(suffix[0]))
}

func shouldUseEntropyValidation(patternName string, cfg patterns.PatternConfig) bool {
	// Provider-scoped imports already require both a provider boundary and an
	// explicit credential assignment. Entropy is useful as a score there, but
	// making it a hard gate rejects valid short and restricted-alphabet tokens.
	if looseProviderName(cfg.Regex) != "" {
		return false
	}
	if cfg.UseEntropy {
		return true
	}

	return strings.Contains(patternName, "password") || strings.Contains(patternName, "session_token")
}

func isObviousCredentialPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{"placeholder", "changeme", "dummy", "your_api", "your-token", "your_token", "redacted"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if len(value) < 8 {
		return false
	}
	unique := make(map[rune]struct{})
	for _, character := range value {
		unique[character] = struct{}{}
	}
	return len(unique) <= 2
}

func isObviousSecretPlaceholder(patternName, value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(patternName, "aws") && strings.HasSuffix(trimmed, "EXAMPLE") {
		return true
	}
	if trimmed == strings.Join([]string{"sk", "test", "4eC39HqLyjWDarjtT1zdp7dc"}, "_") {
		return true
	}

	runCharacter := byte(0)
	runLength := 0
	for index := 0; index < len(trimmed); index++ {
		character := trimmed[index]
		if !isASCIIAlphaNumeric(character) {
			runCharacter = 0
			runLength = 0
			continue
		}
		if character == runCharacter {
			runLength++
		} else {
			runCharacter = character
			runLength = 1
		}
		if runLength >= 12 {
			return true
		}
	}
	return false
}

func specializedBoost(patternName, value string) float64 {
	switch {
	case strings.Contains(patternName, "aws") && strings.HasPrefix(value, "AKIA"):
		return 0.22
	case strings.Contains(patternName, "google_api") && strings.HasPrefix(value, "AIza"):
		return 0.22
	case strings.Contains(patternName, "stripe") && strings.HasPrefix(value, "sk_live_"):
		return 0.20
	case strings.Contains(patternName, "jwt") && strings.HasPrefix(value, "eyJ"):
		return 0.15
	case strings.Contains(patternName, "github") && hasAnyPrefix(value, "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"):
		return 0.22
	case strings.Contains(patternName, "gitlab") && hasAnyPrefix(value,
		"glpat-", "glrt-", "glptt-", "GR1348941", "gloas-", "glft-", "glagent-", "glimt-", "gldt-", "glsoat-", "glcbt-"):
		return 0.20
	case strings.Contains(patternName, "slack") && hasAnyPrefix(value, "xoxb-", "xoxp-", "xapp-", "xwfp-", "xoxe.", "xoxe-"):
		return 0.20
	case strings.Contains(patternName, "cloudflare") && hasAnyPrefix(value, "cfk_", "cfut_", "cfat_"):
		return 0.20
	case strings.Contains(patternName, "sentry") && strings.HasPrefix(value, "sntry"):
		return 0.20
	case strings.Contains(patternName, "postman") && strings.HasPrefix(value, "PMAK-"):
		return 0.20
	default:
		return 0
	}
}

func isKnownStructuredCredential(patternName, value string) bool {
	switch patternName {
	case "discord_webhook":
		return strings.HasPrefix(value, "https://discord.com/api/webhooks/") ||
			strings.HasPrefix(value, "https://discordapp.com/api/webhooks/")
	case "google_cloud_platform":
		return strings.HasSuffix(value, ".apps.googleusercontent.com")
	case "sendgrid_api_key":
		return strings.HasPrefix(value, "SG.")
	case "slack_webhook":
		return strings.HasPrefix(value, "https://hooks.slack.com/services/")
	default:
		return false
	}
}

func hasAnyPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
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

func isPlaceholderEmail(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return false
	}
	local, domain := value[:at], value[at+1:]
	switch domain {
	case "example.com", "example.net", "example.org", "localhost":
		return true
	}
	if strings.HasSuffix(domain, ".test") ||
		strings.HasSuffix(domain, ".example") ||
		strings.HasSuffix(domain, ".invalid") ||
		strings.HasSuffix(domain, ".localhost") {
		return true
	}
	switch local + "@" + domain {
	case "email@domain.com", "name@domain.com", "name@email.com":
		return true
	}
	return false
}

func isObviousPIIPlaceholder(patternName, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if containsAny(value, []string{"placeholder", "redacted", "changeme", "dummy"}) {
		return true
	}

	switch patternName {
	case "person_name":
		normalized := strings.Join(strings.Fields(value), " ")
		switch normalized {
		case "john doe", "jane doe", "test user", "sample user", "example user", "first last", "your name",
			"fulano de tal", "pessoa teste", "usuario teste", "usuário teste", "usuario exemplo", "usuário exemplo",
			"cliente exemplo", "nome sobrenome":
			return true
		}
	case "ipv4_address", "ipv6_address":
		address, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		if address.IsLoopback() || address.IsUnspecified() {
			return true
		}
		for _, rawPrefix := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			prefix := netip.MustParsePrefix(rawPrefix)
			if prefix.Contains(address) {
				return true
			}
		}
	case "mac_address":
		compact := strings.NewReplacer(":", "", "-", "").Replace(value)
		return compact == "000000000000" || compact == "ffffffffffff"
	case "phone_number":
		digits := digitsOnly(value)
		if len(digits) > 10 {
			digits = digits[len(digits)-10:]
		}
		if len(digits) != 10 {
			return false
		}
		if digits == "0123456789" || digits == "1234567890" || strings.Count(digits, digits[:1]) == len(digits) {
			return true
		}
		return digits[3:6] == "555" && digits[6:] >= "0100" && digits[6:] <= "0199"
	case "serial_number":
		compact := strings.Trim(value, "-_ ")
		return compact != "" && strings.Count(compact, compact[:1]) == len(compact)
	case "us_zip_code":
		return value == "00000" || value == "00000-0000"
	}
	return false
}

func isValidPIIShape(patternName, value string) bool {
	switch patternName {
	case "ipv4_address":
		address, err := netip.ParseAddr(value)
		return err == nil && address.Is4()
	case "ipv6_address":
		address, err := netip.ParseAddr(value)
		return err == nil && address.Is6()
	default:
		return true
	}
}

func isValidPaymentCard(value string) bool {
	if strings.ContainsRune(value, '*') {
		return true
	}
	digits := digitsOnly(value)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	double := false
	for index := len(digits) - 1; index >= 0; index-- {
		digit := int(digits[index] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func isValidJWT(value string) bool {
	segments := strings.Split(value, ".")
	if len(segments) != 3 || segments[2] == "" {
		return false
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return false
	}
	algorithm, ok := header["alg"].(string)
	if !ok || strings.TrimSpace(algorithm) == "" {
		return false
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return false
	}
	var claims map[string]any
	return json.Unmarshal(decodedPayload, &claims) == nil && claims != nil
}

func isValidBasicAuth(value string) bool {
	parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return false
	}
	payload := strings.TrimSpace(parts[1])
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
		if err != nil {
			return false
		}
	}
	username, password, present := strings.Cut(string(decoded), ":")
	return present && username != "" && password != ""
}

func digitsOnly(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= '0' && character <= '9' {
			builder.WriteRune(character)
		}
	}
	return builder.String()
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
