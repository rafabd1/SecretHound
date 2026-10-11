package validation

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
)

func TestObviousPIIPlaceholders(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
	}{
		{pattern: "ipv4_address", value: "127.0.0.1"},
		{pattern: "ipv4_address", value: "192.0.2.10"},
		{pattern: "ipv6_address", value: "2001:db8::42"},
		{pattern: "mac_address", value: "00:00:00:00:00:00"},
		{pattern: "phone_number", value: "+1 202-555-0147"},
		{pattern: "person_name", value: "John Doe"},
		{pattern: "person_name", value: "Fulano de Tal"},
		{pattern: "person_name", value: "Pessoa Teste"},
		{pattern: "person_name", value: "Usuário Teste"},
		{pattern: "serial_number", value: "placeholder-01"},
		{pattern: "us_zip_code", value: "00000"},
	}
	for _, test := range tests {
		if !isObviousPIIPlaceholder(test.pattern, test.value) {
			t.Errorf("%s %q was not recognized as an obvious placeholder", test.pattern, test.value)
		}
	}
}

func TestPlausiblePIIValuesAreNotPlaceholders(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
	}{
		{pattern: "ipv4_address", value: "45.77.12.34"},
		{pattern: "ipv6_address", value: "fd12:3456:789a::42"},
		{pattern: "mac_address", value: "02:42:ac:11:00:02"},
		{pattern: "phone_number", value: "+1 404-287-6391"},
		{pattern: "person_name", value: "Marina Costa"},
		{pattern: "person_name", value: "João da Silva"},
		{pattern: "serial_number", value: "NX7Q-4M9K-2P8R"},
		{pattern: "us_zip_code", value: "94107"},
	}
	for _, test := range tests {
		if isObviousPIIPlaceholder(test.pattern, test.value) {
			t.Errorf("%s %q was incorrectly recognized as a placeholder", test.pattern, test.value)
		}
	}
}

func TestPIIContextPenaltiesRemainActive(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["phone_number"]
	pattern := &patterns.CompiledPattern{
		Name:   "phone_number",
		Regex:  regexp.MustCompile(config.Regex),
		Config: config,
	}
	value := "+1 404-287-6391"

	production := EvaluateCandidate(pattern.Name, pattern, value, "customer phone: "+value, Options{})
	if !production.Valid {
		t.Fatalf("plausible phone was rejected: %+v", production)
	}
	noise := EvaluateCandidate(pattern.Name, pattern, value, "test version id port example: "+value, Options{})
	if noise.Valid || noise.Confidence >= production.Confidence {
		t.Fatalf("PII context penalties were ignored: production=%+v noise=%+v", production, noise)
	}
}

func TestPlaceholderEmailUsesOnlyObviousReservedExamples(t *testing.T) {
	for _, value := range []string{
		"alice@example.com",
		"person@service.test",
		"name@domain.com",
	} {
		if !isPlaceholderEmail(value) {
			t.Errorf("%q was not recognized as an obvious placeholder", value)
		}
	}
	for _, value := range []string{
		"first.last@acme.com",
		"test@test.com",
		"alice@examplecorp.com",
		"user@myexamplebank.com",
		"support@domain.com",
		"admin@email.com",
	} {
		if isPlaceholderEmail(value) {
			t.Errorf("%q was incorrectly treated as a placeholder", value)
		}
	}
}

func TestObviousSecretPlaceholderUsesNarrowSignals(t *testing.T) {
	for _, test := range []struct {
		pattern string
		value   string
	}{
		{pattern: "aws_access_key", value: "AKIAIOSFODNN7EXAMPLE"},
		{pattern: "stripe_test_secret_key", value: "sk_test_4eC39HqLyjWDarjtT1zdp7dc"},
		{pattern: "stripe_secret_key", value: "sk_live_TTTTTTTTTTTTTTTTTTTTTTTT"},
		{pattern: "slack_webhook", value: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"},
	} {
		if !isObviousSecretPlaceholder(test.pattern, test.value) {
			t.Errorf("%s %q was not recognized as an obvious placeholder", test.pattern, test.value)
		}
	}

	for _, test := range []struct {
		pattern string
		value   string
	}{
		{pattern: "aws_access_key", value: "AKIAEXAMPLECORP7M4Q2"},
		{pattern: "config_api_key", value: "alice@examplecorp.com"},
		{pattern: "stripe_secret_key", value: "sk_live_T8mQ2xV7nR4tY9uP1kL6cB3h"},
	} {
		if isObviousSecretPlaceholder(test.pattern, test.value) {
			t.Errorf("%s %q was incorrectly recognized as a placeholder", test.pattern, test.value)
		}
	}
}

func TestBasicAuthRequiresACompleteDecodableUserPasswordPair(t *testing.T) {
	pattern := compiledDefaultPattern(t, "basic_auth")
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("service-account:correct-horse-battery-staple"))
	if decision := EvaluateCandidate(pattern.Name, pattern, valid, "Authorization: "+valid, Options{}); !decision.Valid {
		t.Fatalf("valid Basic credential was rejected: %+v", decision)
	}

	for _, value := range []string{
		"Basic " + strings.Repeat("A", 24),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("missing-colon")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("verylongusername:")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte(":verylongpassword")),
	} {
		if decision := EvaluateCandidate(pattern.Name, pattern, value, "Authorization: "+value, Options{}); decision.Valid {
			t.Errorf("invalid Basic credential %q was accepted: %+v", value, decision)
		}
	}
}

func TestPIIEmailEvaluationRejectsOnlyObviousReservedExamples(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["email_address"]
	pattern := &patterns.CompiledPattern{
		Name:   "email_address",
		Regex:  regexp.MustCompile(config.Regex),
		Config: config,
	}

	for _, value := range []string{"alice@example.com", "person@service.test", "name@domain.com"} {
		if decision := EvaluateCandidate(pattern.Name, pattern, value, "email: "+value, Options{}); decision.Valid {
			t.Errorf("reserved example email %q was accepted: %+v", value, decision)
		}
	}
	for _, value := range []string{"first.last@acme.com", "test@test.com", "alice@examplecorp.com", "user@myexamplebank.com"} {
		if decision := EvaluateCandidate(pattern.Name, pattern, value, "customer email: "+value, Options{}); !decision.Valid {
			t.Errorf("plausible email %q was rejected: %+v", value, decision)
		}
	}
}

func TestBashCandidateBypassesSecretShapeHeuristics(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["bash_command_suspicious"]
	pattern := &patterns.CompiledPattern{
		Name:        "bash_command_suspicious",
		Description: config.Description,
		Regex:       regexp.MustCompile(config.Regex),
		Config:      config,
	}
	value := "curl https://cdn.acme.test/install.sh | bash"
	decision := EvaluateCandidate(pattern.Name, pattern, value, "command: "+value, Options{})
	if !decision.Valid || decision.Confidence != 0.80 {
		t.Fatalf("bash command was filtered as a secret candidate: %+v", decision)
	}
}

func TestEntropyValidationKeepsProviderShapedGitHubToken(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["github_fine_grained_token"]
	pattern := &patterns.CompiledPattern{
		Name:        "github_fine_grained_token",
		Description: config.Description,
		Regex:       regexp.MustCompile(config.Regex),
		Config:      config,
	}
	suffix := strings.Repeat("Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk", 3)[:82]
	value := "github_pat_" + suffix

	decision := EvaluateCandidate(pattern.Name, pattern, value, "GITHUB_TOKEN="+value, Options{})
	if !decision.Valid {
		t.Fatalf("provider-shaped GitHub token was rejected: %+v", decision)
	}
}

func TestEntropyValidationKeepsOpaqueCamelCaseToken(t *testing.T) {
	pattern := entropyTestPattern()
	value := "aZ7mQ9xV2nR5tY8uP3kL6cB1hF4jW0zE7Q"

	decision := EvaluateCandidate("api_key_assignment", pattern, value, "api_key = \""+value+"\"", Options{})
	if !decision.Valid {
		t.Fatalf("opaque camelCase token was rejected: %+v", decision)
	}
}

func TestEntropyValidationKeepsUUIDCredential(t *testing.T) {
	pattern := entropyTestPattern()
	value := "123e4567-e89b-42d3-a456-4266141749af"

	decision := EvaluateCandidate("api_key_assignment", pattern, value, "api_key = \""+value+"\"", Options{})
	if !decision.Valid {
		t.Fatalf("UUID-shaped credential was rejected: %+v", decision)
	}
}

func TestGenericTranslationKeyStillRejected(t *testing.T) {
	pattern := entropyTestPattern()
	value := "account_security_settings_title"

	decision := EvaluateCandidate("api_key_assignment", pattern, value, value, Options{})
	if decision.Valid {
		t.Fatalf("translation key was accepted: %+v", decision)
	}
}

func TestGenericCredentialReferenceIsRejected(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["api_key_assignment"]
	pattern := &patterns.CompiledPattern{
		Name:   "api_key_assignment",
		Regex:  regexp.MustCompile(config.Regex),
		Config: config,
	}
	for _, value := range []string{
		"process.env.API_KEY",
		"import.meta.env.OPENAI_API_KEY",
		"config.serviceToken",
	} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, "api_key = "+value, Options{LocalMode: true})
		if decision.Valid {
			t.Errorf("credential reference %q was accepted: %+v", value, decision)
		}
	}
}

func TestLooseProviderPatternRequiresCredentialLabel(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["algoliaadminkey_2"]
	if provider := looseProviderName(config.Regex); provider != "algolia" {
		t.Fatalf("looseProviderName(%q) = %q", config.Regex, provider)
	}
	pattern := &patterns.CompiledPattern{
		Name:   "algoliaadminkey_2",
		Regex:  regexp.MustCompile(config.Regex),
		Config: config,
	}
	value := "A7kQ9mX2vR5tY8uP3nD6cB1hF4jW0zE2"

	for _, context := range []string{
		"algolia buildHash = " + value,
		"algolia searchOnlyKey = " + value,
	} {
		if decision := EvaluateCandidate(pattern.Name, pattern, value, context, Options{}); decision.Valid {
			t.Errorf("provider noise was accepted from %q: %+v", context, decision)
		}
	}
	for _, context := range []string{
		`algolia_admin_key = "` + value + `"`,
		`algoliaAdminKey = "` + value + `"`,
	} {
		if decision := EvaluateCandidate(pattern.Name, pattern, value, context, Options{}); !decision.Valid {
			t.Errorf("credential-labeled provider token was rejected from %q: %+v", context, decision)
		}
	}
}

func TestLooseProviderPatternRequiresProviderBoundary(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["linemessaging"]
	if provider := looseProviderName(config.Regex); provider != "line" {
		t.Fatalf("looseProviderName(%q) = %q", config.Regex, provider)
	}
	pattern := &patterns.CompiledPattern{
		Name:   "line",
		Regex:  regexp.MustCompile(config.Regex),
		Config: config,
	}
	value := strings.Repeat("Ab3dEf6hIj9kLm2nOp5qRs8t", 8)[:171]

	if decision := EvaluateCandidate(pattern.Name, pattern, value, `pipelineApiToken = "`+value+`"`, Options{}); decision.Valid {
		t.Fatalf("provider name matched inside another identifier: %+v", decision)
	}
	if decision := EvaluateCandidate(pattern.Name, pattern, value, `lineApiToken = "`+value+`"`, Options{}); !decision.Valid {
		t.Fatalf("camel-case provider credential label was rejected: %+v", decision)
	}
}

func TestLooseProviderNameHandlesEscapedLiteral(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["datagov"]
	if provider := looseProviderName(config.Regex); provider != "data.gov" {
		t.Fatalf("looseProviderName(%q) = %q", config.Regex, provider)
	}
}

func TestLoadableLooseProviderPatternsUseCredentialGate(t *testing.T) {
	for name, config := range patterns.DefaultPatterns.Patterns {
		if config.Retired || !strings.Contains(config.Regex, ".{0,40}") {
			continue
		}
		if provider := looseProviderName(config.Regex); provider == "" {
			t.Errorf("loadable loose provider pattern %q is not recognized by the credential gate: %q", name, config.Regex)
		}
	}
}

func TestWeb3PrivateKeyRejectsTruncationAndInvalidScalars(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["web3_private_key"]
	re := regexp.MustCompile(config.Regex)
	valid := strings.Repeat("0123456789abcdef", 4)

	for _, input := range []string{
		"private_key=" + valid,
		"private_key=0x" + valid,
	} {
		match := re.FindStringSubmatch(input)
		if len(match) < 2 || (match[1] != valid && match[1] != "0x"+valid) {
			t.Errorf("valid private key was not captured from %q: %#v", input, match)
		}
	}
	if match := re.FindStringSubmatch("private_key=" + valid + "0"); match != nil {
		t.Fatalf("65-digit private key was truncated to a valid-looking value: %#v", match)
	}

	order := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	orderMinusOne := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
	if !isValidWeb3PrivateKey(valid) || !isValidWeb3PrivateKey(orderMinusOne) {
		t.Fatal("valid secp256k1 scalars were rejected")
	}
	for _, value := range []string{strings.Repeat("0", 64), order} {
		if isValidWeb3PrivateKey(value) {
			t.Errorf("invalid secp256k1 scalar %q was accepted", value)
		}
	}
}

func TestURLCandidateIsNotRejectedBySecretHeuristics(t *testing.T) {
	config := patterns.DefaultPatterns.Patterns["url_generic"]
	pattern := &patterns.CompiledPattern{
		Name:        "url_generic",
		Description: config.Description,
		Regex:       regexp.MustCompile(config.Regex),
		Config:      config,
	}
	value := "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
	context := "# Integration examples\nWebhook placeholder: `" + value + "`."

	decision := EvaluateCandidate(pattern.Name, pattern, value, context, Options{LocalMode: true})
	if !decision.Valid || decision.Confidence < 0.5 {
		t.Fatalf("valid URL was rejected by secret heuristics: %+v", decision)
	}
}

func TestURLCandidateStillHonorsPatternExclusions(t *testing.T) {
	exclude := regexp.MustCompile(`(?i)^blocked://`)
	pattern := &patterns.CompiledPattern{
		Name:                   "url_generic",
		Regex:                  regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]+://\S+`),
		CompiledExcludeRegexes: []*regexp.Regexp{exclude},
		Config: patterns.PatternConfig{
			Category:  "url",
			MinLength: 8,
		},
	}

	decision := EvaluateCandidate(pattern.Name, pattern, "blocked://internal/resource", "", Options{})
	if decision.Valid {
		t.Fatalf("URL excluded by its pattern was accepted: %+v", decision)
	}
}

func TestURLDomainIsExtractedFromCodeContext(t *testing.T) {
	pattern := compiledDefaultPattern(t, "generic_domain_name")
	value := "cdn-assets.example.com"
	context := `const api_key = "cdn-assets.example.com"; // Public hostname, not a secret.`

	decision := EvaluateCandidate(pattern.Name, pattern, value, context, Options{LocalMode: true})
	if !decision.Valid || decision.Confidence < 0.5 {
		t.Fatalf("valid domain was rejected by secret heuristics: %+v", decision)
	}
}

func TestURLDomainPatternRejectsAssetFilename(t *testing.T) {
	pattern := compiledDefaultPattern(t, "generic_domain_name")
	for _, value := range []string{"assets.runtime.chunk.js", "assets.runtime.chunk.mjs"} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if decision.Valid {
			t.Errorf("asset filename %q was accepted as a domain: %+v", value, decision)
		}
	}
}

func TestURLDomainPatternKeepsPublicTLDsThatResembleExtensions(t *testing.T) {
	pattern := compiledDefaultPattern(t, "generic_domain_name")
	for _, value := range []string{"cdn.example.zip", "api.example.py", "api.example.ck"} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if !decision.Valid {
			t.Errorf("public domain %q was rejected: %+v", value, decision)
		}
	}
}

func TestHasICANNTLDHandlesWildcardRulesWithoutAcceptingUnknownSuffixes(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "api.example.ck", want: true},
		{value: "cdn.example.zip", want: true},
		{value: "api.example.py", want: true},
		{value: "assets.runtime.chunk.js", want: false},
		{value: "assets.runtime.chunk.mjs", want: false},
	}

	for _, test := range tests {
		if got := hasICANNTLD(test.value); got != test.want {
			t.Errorf("hasICANNTLD(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}

func TestURLCandidateRejectsMalformedAbsoluteURI(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	value := "https://[::1"

	decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
	if decision.Valid {
		t.Fatalf("malformed URI was accepted: %+v", decision)
	}
}

func TestURLCandidateNormalizesProseDelimiter(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	raw := "https://api.example.com/v1/users)."
	want := "https://api.example.com/v1/users"

	if got := NormalizeCandidate(pattern.Name, pattern, raw); got != want {
		t.Fatalf("NormalizeCandidate() = %q, want %q", got, want)
	}
	decision := EvaluateCandidate(pattern.Name, pattern, raw, raw, Options{LocalMode: true})
	if !decision.Valid {
		t.Fatalf("normalized URI was rejected: %+v", decision)
	}
}

func TestURLCandidatePreservesValidTrailingURLPunctuation(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	values := []string{
		"https://api.example.com/v1/users,",
		"https://api.example.com/v1/users;",
		"https://api.example.com/v1/users...",
		"https://api.example.com/?q=a,",
	}

	for _, value := range values {
		if got := NormalizeCandidate(pattern.Name, pattern, value); got != value {
			t.Errorf("NormalizeCandidate(%q) = %q", value, got)
		}
	}
}

func TestRequiredContextSearchUsesOriginalByteOffsets(t *testing.T) {
	context := "z=ȺrEvampcrm"
	if !containsRequiredContextTerm(context, []string{"revampcrm"}) {
		t.Fatalf("ASCII term after Unicode prefix was not found in %q", context)
	}
	if containsRequiredContextTerm("DARK_API_KEY", []string{"ark"}) {
		t.Fatal("substring inside an uppercase identifier crossed its boundary")
	}
	for _, context := range []string{"XAIKey", "KIMIApiKey", "QWENApiKey", "ARKApiKey"} {
		term := strings.TrimSuffix(strings.TrimSuffix(context, "ApiKey"), "Key")
		if !containsRequiredContextTerm(context, []string{term}) {
			t.Errorf("ALLCAPS prefix %q was not recognized in %q", term, context)
		}
	}
	for _, context := range []string{"DARKApiKey", "LANDMARKApiKey"} {
		if containsRequiredContextTerm(context, []string{"ark"}) {
			t.Errorf("ark crossed the identifier start boundary in %q", context)
		}
	}
}

func TestCandidateScopedContextIncludesOnlyImmediateParentObjectLabel(t *testing.T) {
	value := "sk-A7kQ9mX2vR5tY8uP3nD6cB1hF4"
	context := `other: { qwen: "sibling" }, providers: { moonshot: { api_key: "` + value + `" }, qwen: { api_key: "other" } }`
	offset := strings.Index(context, value)
	got := candidateScopedContext(value, context, Options{MatchOffset: offset, HasMatchOffset: true})
	if !strings.Contains(got, "moonshot") || !strings.Contains(got, "api_key") {
		t.Fatalf("parent object label was omitted: %q", got)
	}
	if strings.Contains(got, "qwen") || strings.Contains(got, "providers") {
		t.Fatalf("scoped context included a sibling or grandparent: %q", got)
	}
}

func TestURLCandidateKeepsBalancedDelimiters(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	values := []string{
		"https://[2001:db8::1]/wiki/Function_(mathematics)",
		"https://en.wikipedia.org/wiki/Yahoo!",
		"https://example.com/path)",
		"https://example.com./",
	}
	for _, value := range values {
		if got := NormalizeCandidate(pattern.Name, pattern, value); got != value {
			t.Errorf("NormalizeCandidate(%q) = %q", value, got)
		}
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if !decision.Valid {
			t.Errorf("valid URI %q was rejected: %+v", value, decision)
		}
	}
}

func TestURLCandidateRemovesClosingMarkdownDelimiter(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	raw := "https://docs.example.com/guide)"
	want := "https://docs.example.com/guide"

	if got := NormalizeCandidateWithLeading(pattern.Name, pattern, raw, '('); got != want {
		t.Fatalf("NormalizeCandidateWithLeading() = %q, want %q", got, want)
	}
	if got := NormalizeCandidateWithLeading(pattern.Name, pattern, raw, '"'); got != raw {
		t.Fatalf("ordinary URI ending in ')' was changed to %q", got)
	}
}

func TestURLPathKeepsValidEndpointForms(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_path")
	values := []string{
		"/",
		"/?page=2",
		"/api/v1/users?active=true",
		"/api/users/42:activate",
		"/api/search?next=/users?page=2",
		"/api/openapi.json",
		"/api/examples/list",
		"/assets/app.js",
	}
	for _, value := range values {
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if !decision.Valid {
			t.Errorf("valid URL path %q was rejected: %+v", value, decision)
		}
	}
}

func TestURLCandidateValidatesAuthorityByScheme(t *testing.T) {
	pattern := compiledDefaultPattern(t, "url_generic")
	for _, value := range []string{"https://:80", "https:///missing-host", "mongodb:///orders"} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if decision.Valid {
			t.Errorf("URI with a missing required host %q was accepted: %+v", value, decision)
		}
	}

	for _, value := range []string{"postgresql:///mydb", "sqlite:///tmp/application.db", "unix:///var/run/docker.sock"} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, value, Options{LocalMode: true})
		if !decision.Valid {
			t.Errorf("valid hostless URI %q was rejected: %+v", value, decision)
		}
	}
}

func compiledDefaultPattern(t *testing.T, name string) *patterns.CompiledPattern {
	t.Helper()
	config, ok := patterns.DefaultPatterns.Patterns[name]
	if !ok {
		t.Fatalf("default pattern %q does not exist", name)
	}
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{config.Category}, nil); err != nil {
		t.Fatalf("load %s patterns: %v", config.Category, err)
	}
	pattern, ok := manager.GetCompiledPatterns()[name]
	if !ok {
		t.Fatalf("pattern %q was not loaded", name)
	}
	return pattern
}

func TestCreditCardNumberRequiresLuhnForUnmaskedPAN(t *testing.T) {
	pattern := compiledDefaultPattern(t, "credit_card_number")
	for _, value := range []string{"6011000990139424", "601100******9424"} {
		decision := EvaluateCandidate(pattern.Name, pattern, value, "pan="+value, Options{LocalMode: true})
		if !decision.Valid {
			t.Errorf("valid or masked PAN %q was rejected: %+v", value, decision)
		}
	}

	value := "6011000990139426"
	if decision := EvaluateCandidate(pattern.Name, pattern, value, "pan="+value, Options{LocalMode: true}); decision.Valid {
		t.Fatalf("Luhn-invalid PAN was accepted: %+v", decision)
	}
}

func TestJWTRequiresDecodableJSONHeaderAndPayload(t *testing.T) {
	pattern := compiledDefaultPattern(t, "jwt_token")
	valid := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if decision := EvaluateCandidate(pattern.Name, pattern, valid, "token="+valid, Options{LocalMode: true}); !decision.Valid {
		t.Fatalf("structurally valid JWT was rejected: %+v", decision)
	}

	invalid := "eyJABCDEFGH.IJKLMNOPQR.STUVWXYZ0123456789"
	if decision := EvaluateCandidate(pattern.Name, pattern, invalid, "cacheChunk="+invalid, Options{LocalMode: true}); decision.Valid {
		t.Fatalf("non-JSON JWT-shaped noise was accepted: %+v", decision)
	}
}

func entropyTestPattern() *patterns.CompiledPattern {
	config := patterns.PatternConfig{
		Enabled:          true,
		Category:         "code",
		MinLength:        12,
		UseEntropy:       true,
		MinEntropy:       3.0,
		EntropyMinLength: 12,
	}
	return &patterns.CompiledPattern{
		Name:   "api_key_assignment",
		Regex:  regexp.MustCompile(`[A-Za-z0-9_-]{12,}`),
		Config: config,
	}
}
