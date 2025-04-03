package core

import "regexp"

// InjectDefaultPatternsDirectly injects a set of critical patterns directly
// This is a diagnostic function to bypass the normal loading process
func (rm *RegexManager) InjectDefaultPatternsDirectly() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Ensure we have a clean patterns map
    rm.patterns = make(map[string]*regexp.Regexp)
    
    // Injetar todos os padrões do mapa RegexPatterns global
    for name, pattern := range RegexPatterns {
        re, err := regexp.Compile(pattern)
        if (err == nil) {
            rm.patterns[name] = re
        }
    }
    
    // Adicionar padrões especiais que possam estar faltando
    additionalPatterns := map[string]string{
        // API Keys (caso não existam no RegexPatterns)
        "aws_key":                 `AKIA[0-9A-Z]{16}`,
        "aws_secret":              `(?i)aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key(?:[_-]?id)?['\"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]`,
        "google_api":              `AIza[0-9A-Za-z\-_]{35}`,
        "google_oauth":            `ya29\.[0-9A-Za-z\-_]+`,
        "google_cloud_platform":   `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
        
        // Payment Processors
        "stripe_secret_key":       `sk_live_[0-9a-zA-Z]{24,34}`,
        "stripe_publishable_key":  `pk_live_[0-9a-zA-Z]{24,34}`,
        "stripe_test_key":         `sk_test_[0-9a-zA-Z]{24,34}`,
        
        // Authentication
        "jwt_token":               `eyJ[a-zA-Z0-9_\-\.=]{10,500}`,
        "oauth_token":             `(?i)(?:oauth[._-]?token|access[._-]?token)[\s]*[=:]+[\s]*["']([a-zA-Z0-9_\-\.]{30,})["']|["']([a-zA-Z0-9]{40,})["'][\s]*[:=]+[\s]*(?:oauth|token|true|false)`,
        "basic_auth":              `(?i)(?:basic\s*)(?:[a-zA-Z0-9\+\/=]{5,100})`,
        
        // Versão melhorada do generic_password para evitar falsos positivos
        "generic_password": `(?i)(?:password|passwd|pwd|secret)[\s]*[=:]+[\s]*["']([^'"]{8,30})["'](?!\s+(?:does|don|isn|doesn|match|valid|must))`,
        
        // Modificar o padrão google_oauth_refresh
        "google_oauth_refresh": `(?i)(?:refresh_token|oauth_token)[._-]?[\s]*[=:]+[\s]*["']1/[0-9A-Za-z\-_]{43,64}["']|["']1/[0-9A-Za-z\-_]{43,64}["'][\s]*[:=]+[\s]*(?:true|false|raw)`,
        
        // Modificar o padrão google_measurement_id
        "google_measurement_id": `(?i)(?:google_measurement_id|gtag|gtm_id|ga_tracking_id)[\s]*[=:]+[\s]*["']G-[A-Z0-9]{10}["']|dataLayer\.push\([\s\S]{0,50}["']G-[A-Z0-9]{10}["']`,
        
        // Local file patterns: Adicionar padrões específicos para arquivos locais
        // que detectam configurações típicas em arquivos JavaScript/JSON
        "config_api_key": `['"]?(?:api|app)(?:_|-|\.)?(?:key|token|secret)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
        "config_secret": `['"]?(?:secret|private|auth)(?:_|-|\.)?(?:key|token)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
        "auth_token": `['"]?(?:auth|token|credentials|access)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{8,})['"]`,
        "password_field": `['"]?(?:password|passwd)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]`,
        "mongodb_uri": `(?:mongodb(?:\+srv)?://)[^'"]*:[^'"]*@[^'"]*`,
        "test_private_key": `['"]?(?:private_?key|secret_?key)['"]?\s*[:=]\s*['"]([^'"]{20,})['"]`,
    }
    
    // Adicionar apenas padrões que não existem ainda
    for name, pattern := range additionalPatterns {
        if _, exists := rm.patterns[name]; !exists {
            re, err := regexp.Compile(pattern)
            if err == nil {
                rm.patterns[name] = re
            }
        }
    }
    
    // Ensure exclusions are initialized
    rm.exclusionPatterns = make([]*regexp.Regexp, 0)
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    
    // Adicionar padrões de exclusão globais
    for _, pattern := range ExclusionPatterns {
        re, err := regexp.Compile(pattern)
        if err == nil {
            rm.exclusionPatterns = append(rm.exclusionPatterns, re)
        }
    }
    
    // Adicionar exclusões específicas por padrão
    for patternName, exclusions := range SpecificExclusions {
        var compiledExclusions []*regexp.Regexp
        for _, exclusion := range exclusions {
            re, err := regexp.Compile(exclusion)
            if err == nil {
                compiledExclusions = append(compiledExclusions, re)
            }
        }
        if len(compiledExclusions) > 0 {
            rm.patternExclusions[patternName] = compiledExclusions
        }
    }
    
    // Forçar configuração para arquivos locais
    rm.minSecretLength = 4  // Menor comprimento mínimo
    rm.maxSecretLength = 500 // Maior comprimento máximo
}
