package core

import (
    "bufio"
    "fmt"
    "os"
    "regexp"
    "strings"
)

// RegexPatternMap is a map of predefined regex patterns
var RegexPatternMap = map[string]string{
    // API Keys - melhoradas para serem mais específicas de compatibilidade
    "google_api":               `(?:AIza|GOCSPX)[0-9A-Za-z\-_]{35,40}`,
    "firebase":                 `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
    "firebase_url":             `.*firebaseio\.com`,
    "google_captcha":           `(?:^|[^0-9A-Za-z])6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`,
    "google_oauth":             `(?:^|[^0-9A-Za-z])ya29\.[0-9A-Za-z\-_]+`,

    // AWS - padrões ajustados para evitar falsos positivos
    "amazon_aws_access_key_id": `(?:^|[^0-9A-Za-z])AKIA[0-9A-Z]{16}(?:[^0-9A-Za-z]|$)`,
    "amazon_mws_auth_token":    `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
    "amazon_aws_url":           `(?:^|[^\w/])(s3\.amazonaws\.com/[a-zA-Z0-9_.-]+|[a-zA-Z0-9_.-]+\.s3\.amazonaws\.com)`,
    "amazon_aws_url2":          `(?:^|[^\w/])([a-zA-Z0-9-\._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\._]+|s3-[a-zA-Z0-9-\._/]+|s3\.amazonaws\.com/[a-zA-Z0-9-\._]+|s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-\._]+)`,
    "facebook_access_token":    `EAACEdEose0cBA[0-9A-Za-z]+`,
    "facebook_oauth":           `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`,
    "authorization_basic": 		`(?i)basic\s+[a-zA-Z0-9+/=:_\+\/-]{16,}`,
    "authorization_bearer":     `bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`,
    "authorization_api": 		`(?i)api[_]?key[=:"\s]+[a-zA-Z0-9_\-\.]{16,}`,
    
    // Service keys
    "mailgun_api_key":          `key-[0-9a-zA-Z]{32}`,
    "mailchimp_api_key":        `[0-9a-f]{32}-us[0-9]{1,2}`,
    "twilio_api_key":           `SK[0-9a-fA-F]{32}`,
    "twilio_account_sid": `(^|[^-_a-zA-Z0-9])AC[a-zA-Z0-9_\-]{32}($|[^-_a-zA-Z0-9])`,
	"twilio_app_sid":     `(^|[^-_a-zA-Z0-9])AP[a-zA-Z0-9_\-]{32}($|[^-_a-zA-Z0-9])`,
    "paypal_braintree_access_token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
    "square_oauth_secret":      `sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`,
    "square_access_token":      `sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}|sq0atp-[0-9A-Za-z\-_]{22}`,
    "stripe_standard_api":      `sk_live_[0-9a-zA-Z]{24}`,
    "stripe_restricted_api":    `rk_live_[0-9a-zA-Z]{24}`,
    
    // Git
    "github_access_token":      `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`,
    "github":                   `[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]`,
    
    // Keys & certificates
    "rsa_private_key":          `-----BEGIN RSA PRIVATE KEY-----`,
    "ssh_dsa_private_key":      `-----BEGIN DSA PRIVATE KEY-----`,
    "ssh_ec_private_key":       `-----BEGIN EC PRIVATE KEY-----`,
    "pgp_private_block":        `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
    
    // Tokens
    "json_web_token":           `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`,
    "slack_token":              `xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
    "slack_webhook":            `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
    "SSH_privKey":              `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
    "Heroku API KEY":           `(?i)(heroku[._-]api[._-]key|HEROKU_API_KEY|heroku[._-]token)["\s:=]+[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
    
    // Credenciais - versão simplificada e compatível
    "possible_credentials":     `(?i)(password|passwd|pwd|secret)[ =:]+['"][^'"]{4,30}['"]`,
    
    "cloudinary":               `cloudinary://.*`,
    "aws_api_key":              `AKIA[0-9A-Z]{16}`,
    "password_in_url":          `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\\s]`,
    "picatic_api_key":          `sk_live_[0-9a-z]{32}`,
    "generic_api_key":          `[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]`,
    "generic_secret":           `[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]`,
    
    // Google services
    "google_cloud_platform_api_key": `AIza[0-9A-Za-z\-_]{35}`,
    "google_cloud_platform_oauth": `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
    "google_drive_api_key":     `AIza[0-9A-Za-z\-_]{35}`,
    "google_drive_oauth":       `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
    "google_gcp_service_account": `"type": "service_account"`,
    "google_gmail_api_key":     `AIza[0-9A-Za-z\-_]{35}`,
    "google_gmail_oauth":       `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
    "google_youtube_api_key":   `AIza[0-9A-Za-z\-_]{35}`,
    "google_youtube_oauth":     `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
    
    // Twitter
    "twitter_access_token":     `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
    "twitter_oauth":            `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]`,
    "twitter_bearer":           `AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{37}`,
}

// ExclusionPatterns contém padrões que devem ser excluídos por serem código, não segredos
var ExclusionPatterns = []string{
    // Padrões que devem ser excluídos por serem código, não segredos
    `function\s*\(`,
    `\)\s*{`,
    `\s*var\s+`,
    `\s*const\s+`,
    `\s*let\s+`,
    `console\.log`,
    `module\.exports`,
    `require\(`,
    `import\s+`,
    `export\s+`,
    `return\s+`,
    `if\s*\(`,
    `else\s*{`,
    `for\s*\(`,
    `while\s*\(`,
    `switch\s*\(`,
    `case\s+`,
    `break;`,
    `continue;`,
    `default:`,
    
    // Padrões específicos de código JS minificado
    `function\([\w,\s]*\){\s*`,
    `\[native code\]`,
    `window\.`,
    `document\.`,
    
    // Falsos positivos comuns para Base64
    `base64`,
    `data:image/`,
    `font-face`,
    `@charset`,
    `\*\s*/\s*{`,
    
    // CSS Selectors
    `\.css`,
    `#[a-zA-Z][a-zA-Z0-9_-]*\s*{`,
    `\.[a-zA-Z][a-zA-Z0-9_-]*\s*{`,
    `\[[a-zA-Z][a-zA-Z0-9_-]*\]`,
    
    // Biblioteca jQuery e outras
    `jQuery`,
    `\$\(`,
    `\.ready\(`,
    `\.click\(`,
    `\.on\(`,
    
    // Código minificado
    `function\(t,e`,
    `function\(e,t`,
    `return[a-z]&&`,
    `\?[a-z]\.`,
    `:[a-z]\.`,
}

// Conjunto de exclusões específicas para padrões específicos
var SpecificExclusions = map[string][]string{
    "amazon_aws_url": {
        `selectors`,
        `css3-selectors`,
        `REC-css3-selectors`,
        `w3.org/TR`,
    },
    "amazon_aws_url2": {
        `selectors`,
        `css3-selectors`,
        `REC-css3-selectors`,
        `w3.org/TR`,
    },
    "possible_credentials": {
        `function\s*\(`,
        `\)\s*{`,
        `return`,
        `var\s+`,
        `if\s*\(`,
        `else\s*{`,
        `password:true`,
        `password:!0`,
        `password:null`,
        `password:\s*true`,
        `password:\s*!0`,
        `password:\s*null`,
    },
    "generic_secret": {
        `SECRET_INTERNALS_DO_NOT_USE`,
        `UNSAFE_`,
        `DEPRECATED_`,
        `getSecret`,
        `setSecret`,
        `createSecret`,
        `isSecret`,
        `_secret_`,
    },
    "twilio_account_sid": {
        `base64`,
        `charset`,
        `styles`,
        `background`,
        `data:`,
        `font-face`,
        `@font-face`,
        `eJy`,
        `AAA`,
        `content:`,
        `width:`,
        `height:`,
        `margin:`,
        `padding:`,
    },
    "twilio_app_sid": {
        `base64`,
        `charset`,
        `styles`,
        `background`,
        `data:`,
        `font-face`,
        `@font-face`,
        `eJy`,
        `AAA`,
        `content:`,
        `width:`,
        `height:`,
        `margin:`,
        `padding:`,
    },
    "Heroku API KEY": {
        `target`,
        `id:`,
        `element`,
        `appliesTo`,
        `styleBlockIds`,
        `targets:`,
        `selector`,
        `transformers`,
        `uuid`,
        `guid`,
    },
	"authorization_basic": {
        `chart`,
        `content`,
        `settings`,
        `information`,
        `features`,
        `basic\s+[a-z]+$`,  
        `basic\s+\w+\s+\w+`,
    },
    "authorization_api": {
        `api_language`,
        `api_location`,
        `api\s+fails`,
        `api\s+error`,
        `api\s+request`,
        `location\s+api`,
        `using\s+api`,
        `rest\s+api`,
        `graphql\s+api`,
        `webhook\s+api`,
    },
}

// LoadPredefinedPatterns loads the predefined regex patterns into the RegexManager
func (rm *RegexManager) LoadPredefinedPatterns() error {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Inicializa o mapa se ainda não existir
    if rm.patterns == nil {
        rm.patterns = make(map[string]*regexp.Regexp)
    }
    
    // Inicializa o mapa de exclusões específicas por padrão
    rm.patternExclusions = make(map[string][]*regexp.Regexp)
    
    // Compilar e adicionar padrões principais
    for name, pattern := range RegexPatternMap {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return fmt.Errorf("failed to compile predefined regex '%s': %v", name, err)
        }
        rm.patterns[name] = re
    }
    
    // Compilar padrões de exclusão global
    rm.exclusionPatterns = make([]*regexp.Regexp, 0, len(ExclusionPatterns))
    for _, pattern := range ExclusionPatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            // Log erro mas continue, exclusões são opcionais
            continue
        }
        rm.exclusionPatterns = append(rm.exclusionPatterns, re)
    }
    
    // Compilar e adicionar exclusões específicas para cada padrão
    for patternName, exclusions := range SpecificExclusions {
        // Compilar regex para cada exclusão
        exclusionRegexList := make([]*regexp.Regexp, 0, len(exclusions))
        for _, exclusion := range exclusions {
            re, err := regexp.Compile(exclusion)
            if err == nil {
                exclusionRegexList = append(exclusionRegexList, re)
            }
        }
        
        // Armazenar os patterns de exclusão específicos para este padrão
        if len(exclusionRegexList) > 0 {
            rm.patternExclusions[patternName] = exclusionRegexList
        }
    }
    
    return nil
}

// isValidSecretStrict aplica verificações mais rígidas para conteúdo minificado
func (rm *RegexManager) isValidSecretStrict(value string, patternType string) bool {
    // Aplicar primeiro as verificações básicas
    if !rm.isValidSecret(value, patternType) {
        return false
    }
    
    // Aumentar limite mínimo e reduzir limite máximo
    if len(value) < rm.minSecretLength*2 || len(value) > rm.maxSecretLength/2 {
        return false
    }
    
    // Verificar se contém caracteres típicos de código minificado
    codeChars := []string{"{", "}", ";", "&&", "||", "==", "!=", "=>", "+=", "-="}
    for _, char := range codeChars {
        if strings.Contains(value, char) {
            return false
        }
    }
    
    return true
}

// isExcludedByContextStrict aplica verificação de contexto mais rígida
func (rm *RegexManager) isExcludedByContextStrict(context string, patternName string) bool {
    // Aplicar primeiro verificação básica
    if rm.isExcludedByContext(context) {
        return true
    }
    
    // Verificar exclusões específicas para este padrão
    if exclusions, exists := rm.patternExclusions[patternName]; exists {
        for _, re := range exclusions {
            if re.MatchString(context) {
                return true
            }
        }
    }
    
    return false
}

// ParseRegexFile parses a regex file with a specific format
func ParseRegexFile(filePath string) (map[string]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to open regex file: %v", err)
    }
    defer file.Close()
    
    patterns := make(map[string]string)
    scanner := bufio.NewScanner(file)
    var inPatternSection bool
    
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        
        // Skip empty lines and comments
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        // Check for the start of the pattern section
        if strings.HasPrefix(line, "REGEX_PATTERNS = {") {
            inPatternSection = true
            continue
        }
        
        // Check for the end of the pattern section
        if line == "}" {
            break
        }
        
        // Process pattern lines
        if inPatternSection {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) != 2 {
                continue
            }
            
            // Extract pattern name and regex
            patternName := strings.Trim(parts[0], " '\",")
            patternRegex := strings.Trim(parts[1], " '\",")
            
            // Remove trailing comma if present
            patternRegex = strings.TrimSuffix(patternRegex, ",")
            
            patterns[patternName] = patternRegex
        }
    }
    
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading regex file: %v", err)
    }
    
    if len(patterns) == 0 {
        return nil, fmt.Errorf("no regex patterns found in file")
    }
    
    return patterns, nil
}