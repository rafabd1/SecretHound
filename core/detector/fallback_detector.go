package detector

import (
	"regexp"
	"strings"

	"github.com/rafabd1/SecretHound/core/secret"
)

// FallbackDetector fornece detecção básica quando tudo falhar
type FallbackDetector struct {
	// Padrões críticos que devem ser encontrados mesmo em fallback
	criticalPatterns map[string]*regexp.Regexp
	initialized      bool
}

// NewFallbackDetector cria um detector de fallback
func NewFallbackDetector() *FallbackDetector {
	fd := &FallbackDetector{
		criticalPatterns: make(map[string]*regexp.Regexp),
		initialized:      false,
	}
	
	// Inicializa com padrões mínimos críticos
	fd.initialize()
	
	return fd
}

// initialize configura os padrões críticos
func (fd *FallbackDetector) initialize() {
	if fd.initialized {
		return
	}
	
	// Conjunto mínimo de padrões críticos que devem sempre funcionar
	criticalRegexes := map[string]string{
		"aws_key":        `AKIA[0-9A-Z]{16}`,
		"github_token":   `ghp_[0-9a-zA-Z]{36}`,
		"stripe_key":     `sk_live_[0-9a-zA-Z]{24,34}`,
		"jwt_token":      `eyJ[a-zA-Z0-9_\-\.]{10,500}`,
		"password":       `(?i)password[\s]*[=:]+[\s]*["']([^'"]{8,30})["']`,
	}
	
	for name, pattern := range criticalRegexes {
		re, err := regexp.Compile(pattern)
		if err == nil {
			fd.criticalPatterns[name] = re
		}
	}
	
	fd.initialized = true
}

// DetectWithFallback tenta detectar segredos usando apenas padrões críticos
func (fd *FallbackDetector) DetectWithFallback(content, url string) []secret.Secret {
	var secrets []secret.Secret
	
	// Verifica se a inicialização funcionou
	if !fd.initialized || len(fd.criticalPatterns) == 0 {
		fd.initialize()
	}
	
	// Busca usando padrões críticos
	for name, pattern := range fd.criticalPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) == 0 {
				continue
			}
			
			// Extrai o valor (grupo de captura ou match completo)
			value := match[0]
			if len(match) > 1 && match[1] != "" {
				value = match[1]
			}
			
			// Filtra valores muito curtos 
			if len(value) < 8 {
				continue
			}
			
			// Cria o secret com informações básicas
			s := secret.NewSecret(
				name,
				value,
				extractBasicContext(content, value),
				url,
				0, // Linha desconhecida
			)
			
			secrets = append(secrets, s)
		}
	}
	
	return secrets
}

// extractBasicContext extrai contexto simplificado
func extractBasicContext(content, value string) string {
	idx := strings.Index(content, value)
	if idx == -1 {
		return ""
	}
	
	// Extrai 30 caracteres antes e depois
	start := max(0, idx-30)
	end := min(len(content), idx+len(value)+30)
	
	return content[start:end]
}

// Funções auxiliares
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
