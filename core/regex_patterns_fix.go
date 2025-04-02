package core

import "regexp"

// InjectDefaultPatternsDirectly injects a set of critical patterns directly
// This is a diagnostic function to bypass the normal loading process
func (rm *RegexManager) InjectDefaultPatternsDirectly() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Ensure we have a clean patterns map
    rm.patterns = make(map[string]*regexp.Regexp)
    
    // Expanded pattern set based on the test files content
    expandedPatterns := map[string]string{
        // API Keys
        "aws_key":                 `AKIA[0-9A-Z]{16}`,
        "aws_secret":              `(?i)aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?['\"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]`,
        "google_api":              `AIza[0-9A-Za-z\-_]{35}`,
        "google_oauth":            `ya29\.[0-9A-Za-z\-_]+`,
        "google_cloud_platform":   `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
        
        // Payment Processors
        "stripe_secret_key":       `sk_live_[0-9a-zA-Z]{24,34}`,
        "stripe_publishable_key":  `pk_live_[0-9a-zA-Z]{24,34}`,
        "stripe_test_key":         `sk_test_[0-9a-zA-Z]{24,34}`,
        "stripe_webhook_secret":   `whsec_[a-zA-Z0-9]{32,48}`,
        
        // Authentication
        "jwt_token":               `eyJ[a-zA-Z0-9_\-\.=]{10,500}`,
        "oauth_token":             `(?i)(?:['"]?[a-z0-9_-]+['"]?(?:\s*):(?:\s*)['"]?[a-z0-9!]{30,}['"]?)`,
        "basic_auth":              `(?i)(?:basic\s*)(?:[a-zA-Z0-9\+\/=]{5,100})`,
        
        // Generic patterns
        "simple_api_key":          `['"](?:api_?key|apikey|key|token|secret|credential)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.=]{8,64})['"]`,
        "named_api_key":           `['"](?:api|auth|token|secret|key)_[a-zA-Z]+['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.=]{8,64})['"]`,
        "generic_secret":          `['"](?:secret|private_?key|password|credential)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.=]{8,64})['"]`,
        "password_field":          `['"](?:password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{4,32})['"]`,
        
        // Cloud Providers
        "github_token":            `gh[pous]_[A-Za-z0-9_]{36,255}`,
        "github_oauth":            `github_pat_[A-Za-z0-9_]{82}`,
        "heroku_api_key":          `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
        
        // High entropy strings - keep at the end to avoid capturing already matched patterns
        "high_entropy_string":     `['"]([a-zA-Z0-9+/=_\-]{32,64})['"]`,
    }
    
    // Compile and inject each pattern
    for name, pattern := range expandedPatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            // Skip invalid patterns in diagnostic mode
            continue
        }
        rm.patterns[name] = re
    }
    
    // Ensure exclusions are initialized
    rm.exclusionPatterns = make([]*regexp.Regexp, 0)
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    
    // Reset config to more permissive default values
    rm.minSecretLength = 4
    rm.maxSecretLength = 500
}
