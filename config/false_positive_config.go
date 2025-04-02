package config

import "strings"

// FalsePositiveConfig contém configurações para gerenciar falsos positivos
type FalsePositiveConfig struct {
    // Palavras ou frases que, quando presentes em um potencial segredo, indicam um falso positivo
    ExcludedPhrases []string
    
    // Conjuntos específicos de exclusões para padrões específicos
    PatternSpecificExclusions map[string][]string
    
    // Lista de domínios para os quais determinados padrões serão mais restritivos
    HighNoiseHosts map[string][]string
}

// GetDefaultFalsePositiveConfig retorna a configuração padrão para gerenciamento de falsos positivos
func GetDefaultFalsePositiveConfig() FalsePositiveConfig {
    return FalsePositiveConfig{
        ExcludedPhrases: []string{
            "function", "return", "export", "import", "require", 
            "const", "class", "module", "default", "static",
            "setState", "useState", "component", "render", "effect",
            "getters", "setters", "utils", "helper", "utility",
        },
        
        PatternSpecificExclusions: map[string][]string{
            "messagebird_api_key": {
                "pickers", "Pickers", "Utility", "Class", "getPickersInput",
                "function", "return", "getPickersOutlined", "Outlined",
                "getPickersFilled", "InputBase", "Classes",
            },
            "jwt_token": {
                "function", "example", "placeholder", "test", "demo",
            },
            "high_entropy_string": {
                "function", "return", "export", "import", "require",
                "component", "props", "state", "redux", "context",
            },
        },
        
        HighNoiseHosts: map[string][]string{
            "cdn.jsdelivr.net": {"jwt_token", "high_entropy_string"},
            "unpkg.com": {"jwt_token", "high_entropy_string"},
            "cdnjs.cloudflare.com": {"jwt_token", "high_entropy_string"},
        },
    }
}

// IsFalsePositive determina se um potencial segredo é provavelmente um falso positivo
func (f *FalsePositiveConfig) IsFalsePositive(secretType, secretValue, url string) bool {
    // Verifica frases excluídas gerais
    for _, phrase := range f.ExcludedPhrases {
        if ContainsIgnoreCase(secretValue, phrase) {
            return true
        }
    }
    
    // Verifica exclusões específicas para este tipo de segredo
    if exclusions, exists := f.PatternSpecificExclusions[secretType]; exists {
        for _, exclusion := range exclusions {
            if ContainsIgnoreCase(secretValue, exclusion) {
                return true
            }
        }
    }
    
    // Verificações extras para hosts ruidosos
    for host, patterns := range f.HighNoiseHosts {
        if ContainsIgnoreCase(url, host) {
            for _, pattern := range patterns {
                if pattern == secretType {
                    // Aplicar regras mais rigorosas para hosts ruidosos
                    return !LooksLikeRealSecret(secretType, secretValue)
                }
            }
        }
    }
    
    return false
}

// ContainsIgnoreCase verifica se uma string contém outra, ignorando maiúsculas/minúsculas
func ContainsIgnoreCase(s, substr string) bool {
    s, substr = strings.ToLower(s), strings.ToLower(substr)
    return strings.Contains(s, substr)
}

// LooksLikeRealSecret aplica heurísticas adicionais para verificar se um valor parece um segredo real
func LooksLikeRealSecret(secretType, secretValue string) bool {
    // Implementa lógica mais restritiva para hosts ruidosos
    switch secretType {
    case "jwt_token":
        // JWT tokens reais geralmente têm três partes separadas por pontos
        parts := strings.Split(secretValue, ".")
        return len(parts) == 3 && len(parts[1]) > 10
        
    case "high_entropy_string":
        // Strings de alta entropia reais geralmente não contêm palavras comuns de programação
        codeTerms := []string{
            "function", "return", "const", "var", "let", "import", 
            "export", "require", "module", "component", "react", 
            "angular", "vue", "app", "src", "utils", "helpers",
        }
        
        for _, term := range codeTerms {
            if ContainsIgnoreCase(secretValue, term) {
                return false
            }
        }
        return true
        
    default:
        return true
    }
}
