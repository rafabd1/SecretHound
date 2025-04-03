package utils

import (
    "fmt"
    "regexp"
    "strings"
    "unicode"
)

func IsCommonWord(s string) bool {
    commonWords := []string{
        "password", "username", "function", "return", "export", 
        "import", "require", "module", "class", "const", "default",
        "private", "protected", "public", "static", "application",
        "document", "window", "content", "charset", "modules",
    }
    
    s = strings.ToLower(s)
    for _, word := range commonWords {
        if s == word {
            return true
        }
    }
    
    return false
}

func IsLikelyBase64(s string) bool {
    if len(s) == 0 {
        return false
    }
    
    if len(s)%4 != 0 && !strings.HasSuffix(s, "=") && !strings.HasSuffix(s, "==") {
        return false
    }
    
    base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
    return base64Regex.MatchString(s)
}

func IsLikelyFilePath(s string) bool {
    if strings.Contains(s, "/") || strings.Contains(s, "\\") {
        return strings.Contains(s, ".") || 
               strings.Contains(s, "node_modules") ||
               strings.Contains(s, "dist") ||
               strings.Contains(s, "src") ||
               strings.Contains(s, "modules")
    }
    return false
}

func IsLikelyContentType(s string) bool {
    contentTypePatterns := []string{
        "application/", "text/", "image/", "audio/", "video/",
        "multipart/", "charset=", "content-type", "contentType",
    }
    
    for _, pattern := range contentTypePatterns {
        if strings.Contains(strings.ToLower(s), pattern) {
            return true
        }
    }
    
    return false
}

func HasCommonCodePattern(s string) bool {
    patterns := []string{
        "function", "return", "const ", "var ", "let ", 
        "import ", "export ", "require(", "module.", "class ",
        "interface ", "typeof ", "console.", "window.", "document.",
    }
    
    for _, pattern := range patterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

/* 
 * Checks if a string appears to be a translation/internationalization key
 */
func IsLikelyTranslationKey(s string) bool {
    translationIndicators := []string{
        "_text", "_msg", "_message", "_label", "_title", "_description", 
        "_error", "_info", "_hint", "_help", "_tooltip", "_placeholder",
        "_button", "_link", "_heading", "_flash", "_notification", 
        "_trend", "_chart", "_enabled", "_disabled", "_by_", "_and_",
    }
    
    for _, indicator := range translationIndicators {
        if strings.Contains(strings.ToLower(s), indicator) {
            return true
        }
    }
    
    if strings.Count(s, "_") >= 3 || strings.Count(s, ".") >= 2 {
        return true
    }
    
    return false
}

/* 
 * Performs a comprehensive check if a value appears to be a valid secret candidate
 */
func IsValidSecretCandidate(secretType, value, context string) bool {
    minLength := 8
    switch secretType {
    case "aws_key", "stripe_api_key", "google_api":
        minLength = 16
    case "jwt_token", "bearer_token":
        minLength = 20
    }
    
    if len(value) < minLength {
        return false
    }
    
    if IsLikelyTranslationKey(value) {
        return false
    }
    
    if HasCommonCodePattern(value) {
        return false
    }
    
    if IsLikelyFilePath(value) || IsLikelyContentType(value) {
        return false
    }
    
    if strings.Count(value, "-") >= 4 || strings.Count(value, ".") >= 5 {
        if strings.Count(value, "-") == 4 && len(value) >= 32 && len(value) <= 36 {
            dashPositions := []int{8, 13, 18, 23}
            isUUID := true
            
            for _, pos := range dashPositions {
                if pos >= len(value) || value[pos] != '-' {
                    isUUID = false
                    break
                }
            }
            
            if isUUID {
                return false
            }
        }
    }
    
    return true
}

func IsTimeZoneData(s string) bool {
    timeZoneIndicators := []string{
        "GMT", "UTC", "EST", "CST", "MST", "PST", "CET", "MSD",
        "Africa/", "America/", "Asia/", "Europe/", "Pacific/",
        "|LMT|", "|GMT|", "|BST|", "|CET|", "|CEST|",
    }
    
    lowerS := strings.ToLower(s)
    for _, indicator := range timeZoneIndicators {
        if strings.Contains(lowerS, strings.ToLower(indicator)) {
            return true
        }
    }
    
    digitPatterns := []string{
        "01212", "12121", "01010", "10101", "76767", "67676",
    }
    
    for _, pattern := range digitPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

/* 
 * Checks if a string looks like minified code variable sequence 
 */
func IsMinifiedVariableSequence(s string) bool {
    patterns := []*regexp.Regexp{
        regexp.MustCompile(`[A-Z][0-9][A-Z][0-9]`),
        regexp.MustCompile(`[a-z][A-Z][0-9][a-z][A-Z]`),
        regexp.MustCompile(`[A-Z]{1,2}[0-9]{1,2}[A-Z]{1,2}`),
    }
    
    matchCount := 0
    for _, pattern := range patterns {
        matches := pattern.FindAllString(s, -1)
        matchCount += len(matches)
        
        if matchCount >= 3 {
            return true
        }
    }
    
    segments := splitCamelOrNumberCase(s)
    if len(segments) >= 5 {
        shortSegmentCount := 0
        for _, segment := range segments {
            if len(segment) <= 3 {
                shortSegmentCount++
            }
        }
        
        if float64(shortSegmentCount)/float64(len(segments)) > 0.7 {
            return true
        }
    }
    
    return false
}

/* 
 * Splits a string at camel case boundaries or number sequences 
 */
func splitCamelOrNumberCase(s string) []string {
    if s == "" {
        return []string{}
    }
    
    var result []string
    var current strings.Builder
    
    addCurrent := func() {
        if current.Len() > 0 {
            result = append(result, current.String())
            current.Reset()
        }
    }
    
    prevIsUpper := false
    prevIsLower := false
    prevIsDigit := false
    
    for i, r := range s {
        isUpper := unicode.IsUpper(r)
        isLower := unicode.IsLower(r)
        isDigit := unicode.IsDigit(r)
        
        if i == 0 {
            current.WriteRune(r)
            prevIsUpper = isUpper
            prevIsLower = isLower
            prevIsDigit = isDigit
            continue
        }
        
        if (prevIsLower && isUpper) || 
           (prevIsUpper && isLower && i >= 2 && unicode.IsUpper(rune(s[i-2]))) ||
           (prevIsDigit && !isDigit) || 
           (!prevIsDigit && isDigit) {
            addCurrent()
        }
        
        current.WriteRune(r)
        prevIsUpper = isUpper
        prevIsLower = isLower
        prevIsDigit = isDigit
    }
    
    addCurrent()
    
    return result
}

func IsLikelyUnicodePlaneReference(content string) bool {
    unicodeTerms := []string{
        "Basic Multilingual Plane", "BMP", "surrogate pair",
        "code point", "Unicode", "UTF-16", "UTF-8", "character encoding",
    }
    
    lowerContent := strings.ToLower(content)
    for _, term := range unicodeTerms {
        if strings.Contains(lowerContent, strings.ToLower(term)) {
            return true
        }
    }
    
    return false
}

/* 
 * Checks if a pattern appears in minified code context 
 */
func IsPatternInMinifiedCode(value, context string) bool {
    minifiedIndicators := []string{
        "++", "--", "==", "===", "!=", "!==", "+=", "-=", "*=", "/=",
        ".push(", ".pop(", ".shift(", ".map(", ".filter(", ".forEach(",
        "function(", "return ", ";var ", ";let ", ";const ", "&&", "||",
    }
    
    indicatorCount := 0
    for _, indicator := range minifiedIndicators {
        if strings.Contains(context, indicator) {
            indicatorCount++
            if indicatorCount >= 3 {
                return true
            }
        }
    }
    
    minifiedVarPatterns := []string{
        `[a-z]\.[a-z]\.[a-z]`,
        `[a-z]\([a-z],[a-z]\)`,
        `var [a-z]=[^;]+,[a-z]=`,
    }
    
    for _, pattern := range minifiedVarPatterns {
        if regexp.MustCompile(pattern).MatchString(context) {
            return true
        }
    }
    
    if regexp.MustCompile(`^[A-Za-z][0-9][A-Za-z][0-9]`).MatchString(value) ||
       regexp.MustCompile(`[a-z][A-Z][0-9][a-z][A-Z]`).MatchString(value) {
        return true
    }
    
    return false
}

func IsGoogleAnalyticsID(value string) bool {
    if !regexp.MustCompile(`^G-[A-Z0-9]{10}$`).MatchString(value) {
        return false
    }
    
    if regexp.MustCompile(`G-\d{1,2}[A-Z]{1,2}\d{1,2}[A-Z]{1,2}\d{1,2}`).MatchString(value) {
        return false
    }
    
    return true
}

func IsOAuthTokenInValidContext(value, context string) bool {
    authIndicators := []string{
        "oauth", "token", "access_token", "refresh_token", "bearer", 
        "authentication", "authorization", "credentials",
    }
    
    indicatorCount := 0
    for _, indicator := range authIndicators {
        if strings.Contains(strings.ToLower(context), indicator) {
            indicatorCount++
        }
    }
    
    return indicatorCount >= 2
}

func IsLikelyCSS(s string) bool {
    if strings.HasPrefix(s, "--") {
        return true
    }
    
    cssPatterns := []string{
        "-background-", "-color", "-radius", "-distance", "-shadow",
        "-border-", "-margin-", "-padding-", "-font-", "-size-",
        "-hover", "-active", "-focus", "-selected", "-disabled",
    }
    
    for _, pattern := range cssPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

func IsLikelyBase64Data(s string) bool {
    if strings.Contains(s, "data:image") || 
       strings.Contains(s, "base64") {
        return true
    }
    
    if len(s) > 40 && IsLikelyBase64(s) {
        return true
    }
    
    return false
}

func IsUUID(s string) bool {
    uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
    return uuidRegex.MatchString(s)
}

func HasRepeatedCharacterPattern(s string) bool {
    if len(s) < 20 {
        return false
    }
    
    var prevChar rune
    runLength := 1
    maxRunLength := 0
    
    for i, char := range s {
        if i > 0 {
            if char == prevChar {
                runLength++
            } else {
                runLength = 1
            }
        }
        
        if runLength > maxRunLength {
            maxRunLength = runLength
        }
        
        prevChar = char
    }
    
    if maxRunLength >= 6 {
        return true
    }
    
    charCounts := make(map[rune]int)
    for _, char := range s {
        charCounts[char]++
    }
    
    if len(charCounts) <= 5 && len(s) >= 30 {
        for _, count := range charCounts {
            if float64(count)/float64(len(s)) > 0.3 {
                return true
            }
        }
    }
    
    return false
}

func IsLikelyDocumentation(s, context string) bool {
    docKeywords := []string{
        "example", "usage", "documentation", "wiki", "github.com", 
        "http://", "https://", "/docs/", "/documentation/", 
        "@example", "@caption", "@see", "@link", "sample", "tutorial",
    }
    
    for _, keyword := range docKeywords {
        if strings.Contains(strings.ToLower(s), keyword) || 
           strings.Contains(strings.ToLower(context), keyword) {
            return true
        }
    }
    
    return false
}

func IsLikelyI18nKey(s string) bool {
    if strings.Count(s, "_") >= 2 && len(s) > 20 {
        return true
    }
    
    i18nPrefixes := []string{
        "message_", "label_", "error_", "success_", "button_",
        "placeholder_", "tooltip_", "hint_", "alert_", "text_",
        "title_", "description_", "header_", "footer_", "nav_",
        "min_", "max_", "app_", "page_", "dialog_", "LOGIN.",
        "freshchat_", "ui_", "validation_",
    }
    
    for _, prefix := range i18nPrefixes {
        if strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
            return true
        }
    }
    
    return false
}

func IsLikelyFunctionName(s string) bool {
    functionRegex := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+$`)
    if functionRegex.MatchString(s) {
        return true
    }
    
    actionVerbs := []string{
        "get", "set", "update", "delete", "create", "find", "fetch",
        "compute", "calculate", "validate", "parse", "format", "convert",
        "transform", "handle", "process", "initialize", "start", "stop",
        "transition", "register", "unregister", "subscribe", "unsubscribe",
    }
    
    for _, verb := range actionVerbs {
        if strings.HasPrefix(strings.ToLower(s), verb) {
            return true
        }
    }
    
    return false
}

/* 
 * Checks if a string contains "Basic" as part of authentication syntax or documentation 
 */
func IsLikelyBasicAuthSyntax(value, context string) bool {
    if value == "Basic" || value == "Basic " || strings.HasPrefix(value, "Basic usage") {
        return true
    }
    
    docPatterns := []string{
        "@example", "example", "caption", "sample", "usage",
        "<caption>", "documentation",
    }
    
    for _, pattern := range docPatterns {
        if strings.Contains(strings.ToLower(context), pattern) {
            return true
        }
    }
    
    if strings.HasPrefix(value, "Basic ") {
        credentials := strings.TrimPrefix(value, "Basic ")
        if IsLikelyBase64(credentials) && len(credentials) > 10 {
            return false
        }
    }
    
    return true
}

func IsLikelyUrl(s string) bool {
    urlPatterns := []string{
        ".com/", ".io/", ".net/", ".org/", ".edu/", ".gov/",
        "/api/", "/docs/", "/sdk/", "/plugins/", "/wiki/",
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    }
    
    for _, pattern := range urlPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    
    return false
}

func IsJavaScriptFunction(s string) bool {
    verbPrefixes := []string{
        "get", "set", "update", "create", "delete", "remove", "handle", "process",
        "parse", "format", "convert", "validate", "verify", "check", "is", "has",
        "can", "should", "will", "did", "fetch", "load", "save", "store", "cache",
        "transition", "transform", "enable", "disable", "toggle", "show", "hide",
        "open", "close", "start", "stop", "begin", "end", "init", "setup", "enroll",
        "authenticate", "authorize", "login", "logout", "register", "subscribe",
        "unsubscribe", "connect", "disconnect", "mount", "unmount", "render", "display",
    }
    
    if regexp.MustCompile(`^[a-z][a-zA-Z0-9]*([A-Z][a-zA-Z0-9]*)+$`).MatchString(s) {
        for _, prefix := range verbPrefixes {
            if strings.HasPrefix(strings.ToLower(s), prefix) {
                return true
            }
        }
        
        components := []string{
            "component", "element", "handler", "listener", "callback", 
            "effect", "reducer", "action", "selector", "container",
            "provider", "consumer", "context", "fragment", "memo", "ref",
        }
        
        events := []string{
            "Mount", "Unmount", "Update", "Change", "Click", "Submit", 
            "Focus", "Blur", "KeyDown", "KeyUp", "MouseOver", "MouseOut",
            "TouchStart", "TouchEnd", "Drag", "Drop", "Resize", "Scroll",
        }
        
        for _, comp := range components {
            for _, event := range events {
                pattern := comp + event
                if strings.Contains(s, pattern) {
                    return true
                }
                
                eventPatterns := []string{"Did" + event, "Will" + event, "On" + event, "After" + event, "Before" + event}
                for _, ep := range eventPatterns {
                    if strings.Contains(s, ep) {
                        return true
                    }
                }
            }
        }
    }
    
    authPatterns := []string{
        "MFA", "2FA", "TwoFactor", "MultiFactorAuth", "AuthFactor",
        "Verify", "Validate", "Authenticate", "Authorize", "Token",
        "Credential", "Password", "Login", "Logout", "Session",
        "Remember", "Forgot", "Reset", "Change", "Update", "Check",
    }
    
    for _, pattern := range authPatterns {
        if regexp.MustCompile(fmt.Sprintf(`(?i)(transition|verify|enable|display|is|has|can)[A-Z][a-zA-Z]*%s`, pattern)).MatchString(s) {
            return true
        }
        
        if regexp.MustCompile(fmt.Sprintf(`(?i)(is|has|can|should|will|did)%s[A-Z][a-zA-Z]*`, pattern)).MatchString(s) {
            return true
        }
    }
    
    return false
}

func IsJavaScriptConstant(s string) bool {
    if regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(s) {
        return true
    }
    
    if regexp.MustCompile(`^[A-Z][A-Z0-9_]*_[A-Z][A-Z0-9_]*$`).MatchString(s) {
        return true
    }
    
    constPrefixes := []string{
        "DEFAULT_", "MAX_", "MIN_", "REQUIRED_", "OPTIONAL_", "CONFIG_",
        "TYPE_", "MODE_", "STATE_", "STATUS_", "EVENT_", "ACTION_",
        "ERROR_", "SUCCESS_", "WARNING_", "INFO_", "DEBUG_", "LOG_",
        "AUTH_", "USER_", "ADMIN_", "CLIENT_", "SERVER_", "APP_",
        "PERMISSION_", "ROLE_", "FEATURE_", "FLAG_", "TOGGLE_",
    }
    
    for _, prefix := range constPrefixes {
        if strings.HasPrefix(s, prefix) {
            return true
        }
    }
    
    return false
}

func IsLikelyMinifiedCode(content string) bool {
    newlineCount := strings.Count(content, "\n")
    if len(content) > 200 && newlineCount < len(content)/200 {
        return true
    }
    
    semicolonCount := strings.Count(content, ";")
    if newlineCount > 0 && semicolonCount > newlineCount*3 {
        return true
    }
    
    compressedVarPattern := regexp.MustCompile(`[a-z]\.[a-z]\.|[a-z]\([a-z],[a-z]\)|var [a-z]=[^;]+,[a-z]=|[a-z]\+\+|[a-z]--`)
    if compressedVarPattern.FindString(content) != "" {
        return true
    }
    
    minificationPatterns := []string{
        "}function", "};function", ";var ", ";let ", ";const ",
        "return ", ".push(", ".pop(", ".shift(", ".map(", ".filter(",
        "function(", "=>", "&&", "||",
    }
    
    matchCount := 0
    for _, pattern := range minificationPatterns {
        if strings.Contains(content, pattern) {
            matchCount++
        }
        
        if matchCount >= 3 {
            return true
        }
    }
    
    return false
}

func HasJavaScriptCamelCasePattern(s string) bool {
    if !regexp.MustCompile(`^[a-z][a-zA-Z0-9]*([A-Z][a-zA-Z0-9]*)+$`).MatchString(s) {
        return false
    }
    
    commonWords := []string{
        "transition", "verify", "enable", "disable", "display", "update", "create",
        "delete", "remove", "get", "set", "handle", "process", "parse", "format",
        "convert", "validate", "check", "is", "has", "can", "should", "will", "did",
        "fetch", "load", "save", "store", "cache", "transform", "toggle", "show",
        "hide", "open", "close", "start", "stop", "begin", "end", "init", "setup",
        "register", "subscribe", "unsubscribe", "connect", "disconnect", "mount",
        "unmount", "render", "component", "element", "handler", "listener", "callback",
        "effect", "reducer", "action", "selector", "container", "provider", "consumer",
        "context", "fragment", "memo", "ref", "state", "props", "hook", "custom",
        "use", "bind", "apply", "call", "memoize", "debounce", "throttle",
        "MFA", "2FA", "TwoFactor", "Auth", "Factor", "Token", "Credential", "Password",
        "Login", "Logout", "Session", "Remember", "Forgot", "Reset", "Change", "Update",
    }
    
    words := splitCamelCase(s)
    
    for _, word := range words {
        for _, common := range commonWords {
            if strings.EqualFold(word, common) {
                return true
            }
        }
    }
    
    return false
}

func splitCamelCase(s string) []string {
    var words []string
    var currentWord strings.Builder
    
    for i, char := range s {
        if i > 0 && unicode.IsUpper(char) {
            words = append(words, currentWord.String())
            currentWord.Reset()
        }
        currentWord.WriteRune(char)
    }
    
    if currentWord.Len() > 0 {
        words = append(words, currentWord.String())
    }
    
    return words
}

/* 
 * Checks if a string appears to be an Origin Trial token based on context indicators 
 */
func IsLikelyOriginTrialToken(value, context string) bool {
    originTrialIndicators := []string{
        "origin-trial", "originTrial", 
        "content=", "meta http-equiv", 
        "feature", "expiry", "isThirdParty", 
        "recaptcha", "gstatic", "google",
    }
    
    contextLower := strings.ToLower(context)
    indicatorCount := 0
    
    for _, indicator := range originTrialIndicators {
        if strings.Contains(contextLower, indicator) {
            indicatorCount++
        }
    }
    
    return indicatorCount >= 2
}

func IsVariableReference(value, context string) bool {
    variablePatterns := []string{
        ".accessToken", 
        "=access_token", 
        ":access_token",
        "oauth_token=",
        
        "accessToken:",
        "token:",
        "credential:",
        
        "\"accessToken\"",
        "'accessToken'",
    }
    
    for _, pattern := range variablePatterns {
        if strings.Contains(value, pattern) {
            return true
        }
    }
    
    assignmentPattern := regexp.MustCompile(`^\s*[a-zA-Z0-9_]+\s*[.:=]\s*[a-zA-Z0-9_\.]+\s*$`)
    return assignmentPattern.MatchString(value)
}

func IsUITextOrLabel(value, context string) bool {
    uiLabels := []string{
        "Change password", "Reset password", "Forgot password",
        "Change Password", "Reset Password", "Forgot Password",
        "changingPassword", "resetPassword", "forgotPassword",
    }
    
    for _, label := range uiLabels {
        if value == label {
            return true
        }
    }
    
    uiContexts := []string{
        "createElement", "component", "render", "label", 
        "button", "form", "input", "<label", "<input", 
        "type=\"password\"", "type=\"text\"", "placeholder",
    }
    
    contextLower := strings.ToLower(context)
    for _, uiContext := range uiContexts {
        if strings.Contains(contextLower, strings.ToLower(uiContext)) {
            return true
        }
    }
    
    return false
}

func IsUnicodeReference(value, context string) bool {
    unicodeTerms := []string{
        "Unicode", "UTF", "UTF-8", "UTF-16", "BMP", "Basic Multilingual",
        "Surrogate", "Code Point", "Encoding", "Character Set", "Charset",
        "fromCharCode", "charCodeAt",
    }
    
    for _, term := range unicodeTerms {
        if strings.Contains(value, term) {
            return true
        }
        
        if strings.Contains(context, term) {
            return true
        }
    }
    
    return false
}

func IsGoogleFontApiKey(value, context string) bool {
    if !strings.HasPrefix(value, "AIza") {
        return false
    }
    
    googleFontsIndicators := []string{
        "googleapis.com/webfonts", 
        "fonts.googleapis.com",
        "google.fonts",
        "webfonts",
        "fonts?key=",
    }
    
    for _, indicator := range googleFontsIndicators {
        if strings.Contains(context, indicator) {
            return true
        }
    }
    
    return false
}

func IsDOMSelectorOrPseudo(value, context string) bool {
    pseudoClasses := []string{
        ":hover", ":active", ":focus", ":checked", ":disabled", 
        ":enabled", ":first-child", ":last-child", ":nth-child",
        ":radio", ":checkbox", ":file", ":password", ":image",
    }
    
    for _, pseudo := range pseudoClasses {
        if strings.Contains(value, pseudo) || value == strings.TrimPrefix(pseudo, ":") {
            return true
        }
    }
    
    selectorContexts := []string{
        "querySelector", "querySelectorAll", "getElementById", 
        "getElementsBy", "$('", "$(\"", "jQuery", "selector",
        "pseudos", "Expr.pseudos", "input[type=",
    }
    
    for _, selectorContext := range selectorContexts {
        if strings.Contains(context, selectorContext) {
            return true
        }
    }
    
    return false
}

func IsUIHeaderOrTitle(value, context string) bool {
    uiHeaderTerms := []string{
        "authorization", "authentication", "configuration", "settings",
        "credentials", "login", "register", "profile", "account",
        "security", "management", "overview", "details", "information",
    }
    
    uiHeaderComponents := []string{
        "<h1", "<h2", "<h3", "<h4", "<h5", "<h6",
        "createElement(\"h", "createElement('h", ".createElement(h",
        "title>", "<title", "header>", "<header",
    }
    
    for _, component := range uiHeaderComponents {
        if strings.Contains(context, component) {
            if strings.HasPrefix(value, "Basic ") {
                suffix := strings.TrimPrefix(value, "Basic ")
                
                for _, term := range uiHeaderTerms {
                    if strings.EqualFold(suffix, term) {
                        return true
                    }
                }
            }
            
            for _, term := range uiHeaderTerms {
                if strings.HasPrefix(strings.ToLower(value), "basic "+term) {
                    return true
                }
            }
        }
    }
    
    return false
}

/* 
 * Validates if a string looks like a proper JWT token with three parts 
 */
func IsValidJWTToken(value string) bool {
    parts := strings.Split(value, ".")
    
    if len(parts) != 3 {
        return false
    }
    
    for _, part := range parts {
        if !IsLikelyBase64(part) {
            return false
        }
    }
    
    if len(parts[0]) < 10 || len(parts[1]) < len(parts[0]) {
        return false
    }
    
    if len(parts[2]) < 16 {
        return false
    }
    
    if !strings.HasPrefix(parts[0], "eyJ") || 
        !regexp.MustCompile(`[A-Za-z0-9_\-]+[=]{0,2}$`).MatchString(parts[2]) {
        return false
    }
    
    return true
}

func IsInMinifiedCode(value, context string) bool {
    if len(context) > 100 && strings.Count(context, "\n") < 3 {
        return true
    }
    
    operatorCount := 0
    operatorPatterns := []string{
        "++", "--", "+=", "-=", "*=", "/=", 
        "==", "===", "!=", "!==", ">=", "<=",
        "&&", "||", ">>", "<<", ">>>", "<<=",
    }
    
    for _, op := range operatorPatterns {
        operatorCount += strings.Count(context, op)
    }
    
    if operatorCount > 5 {
        return true
    }
    
    minifiedPatterns := []string{
        ";var ", ";let ", ";const ", ";function", 
        "function(", "return ", "+function",
        "}(", "({", "})", ":[", ",function", 
        "=[", "={", "=function",
    }
    
    patternCount := 0
    for _, pattern := range minifiedPatterns {
        if strings.Contains(context, pattern) {
            patternCount++
        }
    }
    
    return patternCount >= 3
}

func IsBase64StringFragment(value, context string) bool {
    if !strings.Contains(value, ".") {
        return true
    }
    
    if len(value) < 30 {
        return true
    }
    
    parts := strings.Split(value, ".")
    if len(parts) != 3 {
        return true
    }
    
    base64Fragments := regexp.MustCompile(`[A-Za-z0-9+/]{30,}={0,2}`).FindAllString(context, -1)
    
    if len(base64Fragments) > 0 {
        for _, fragment := range base64Fragments {
            if len(fragment) > len(value) && strings.Contains(fragment, value) {
                return true
            }
        }
    }
    
    beforeAfterLength := 15 
    valuePos := strings.Index(context, value)
    
    if valuePos >= 0 {
        startPos := max(0, valuePos-beforeAfterLength)
        endPos := min(len(context), valuePos+len(value)+beforeAfterLength)
        
        surrounding := context[startPos:endPos]
        
        stringPatterns := []string{
            "'", "\"", "+", "=", ":",
            "{", "}", "[", "]",
            "var ", "let ", "const ",
        }
        
        matchCount := 0
        for _, pattern := range stringPatterns {
            if strings.Contains(surrounding, pattern) {
                matchCount++
            }
        }
        
        if matchCount >= 3 {
            return true
        }
    }
    
    if strings.Contains(context, "content=") || strings.Contains(context, "origin") || 
        strings.Contains(context, "feature") || strings.Contains(context, "recaptcha") {
        return true
    }
    
    if IsInMinifiedCode(value, context) {
        authIndicators := []string{
            "token", "jwt", "auth", "login", "user", "session", "claim",
            "authorization", "authenticate", "identity", "credential", "bearer",
        }
        
        hasAuthIndicator := false
        for _, indicator := range authIndicators {
            if strings.Contains(strings.ToLower(context), indicator) {
                hasAuthIndicator = true
                break
            }
        }
        
        if !hasAuthIndicator {
            return true
        }
    }
    
    return false
}

/* 
 * Checks if a string is a long base64 string in JavaScript code context 
 */
func IsLongBase64InJSCode(value, context string) bool {
    if len(value) < 40 {
        return false
    }
    
    if !regexp.MustCompile(`^[A-Za-z0-9+/=]+$`).MatchString(value) {
        return false
    }
    
    jsCodePatterns := []string{
        "function", "return", "var ", "let ", "const ", "=>", 
        "true", "false", "null", "undefined",
        "+", "=", ";", "{", "}", "[", "]", 
        
        "base64", "encode", "decode", "JSON", "data:",
        "toString", "btoa", "atob", "charAt", 
        
        ".min.js", "bundle", "webpack", "rollup", "terser",
    }
    
    patternMatches := 0
    for _, pattern := range jsCodePatterns {
        if strings.Contains(context, pattern) {
            patternMatches++
            if patternMatches >= 3 {
                return true
            }
        }
    }
    
    return false
}
