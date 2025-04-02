package core

import "regexp"

// InjectDefaultPatternsDirectly injects a set of critical patterns directly
// This is a diagnostic function to bypass the normal loading process
func (rm *RegexManager) InjectDefaultPatternsDirectly() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Ensure we have a clean patterns map
    rm.patterns = make(map[string]*regexp.Regexp)
    
    // Add a few critical patterns for testing
    simplePatterns := map[string]string{
        "simple_api_key":        `['"](api_key|apikey|key|token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.=]{16,64})['"]`,
        "simple_secret":         `['"](secret|private_key|password)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.=]{8,64})['"]`,
        "simple_password":       `['"](password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{4,32})['"]`,
        "aws_key":               `AKIA[0-9A-Z]{16}`,
        "stripe_key":            `(sk|pk)_(test|live)_[0-9a-zA-Z]{24,34}`,
        "high_entropy_string":   `(['"])([a-zA-Z0-9+/=_\-]{32,64})(['"])`,
        "jwt_token":             `eyJ[a-zA-Z0-9_\-\.=]{10,500}`,
    }
    
    // Compile and inject each pattern
    for name, pattern := range simplePatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            // Just log and continue in diagnostic mode
            continue
        }
        rm.patterns[name] = re
    }
    
    // Ensure exclusions is initialized
    rm.exclusionPatterns = make([]*regexp.Regexp, 0)
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    
    // Reset config to simplest default
    rm.minSecretLength = 4
    rm.maxSecretLength = 256
}
