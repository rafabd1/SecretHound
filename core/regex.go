package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/utils"
)

// RegexManager gerencia padrões de expressões regulares para detecção de segredos
type RegexManager struct {
	patternManager     *patterns.PatternManager
	minSecretLength    int
	maxSecretLength    int
	isLocalFileMode    bool
	excludedExtensions []string
	mu                 sync.RWMutex
}

// NewRegexManager cria uma nova instância do gerenciador de regex
func NewRegexManager() *RegexManager {
	rm := &RegexManager{
		patternManager:     patterns.NewPatternManager(),
		minSecretLength:    5,
		maxSecretLength:    200,
		excludedExtensions: []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"},
		mu:                 sync.RWMutex{},
	}
	
	// Registra este gerenciador globalmente para poder ser redefinido se necessário
	RegisterRegexManager(rm)
	
	return rm
}

// FindSecrets busca segredos usando os padrões regex configurados
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
	rm.mu.RLock()
	patternCount := rm.patternManager.GetPatternCount()
	rm.mu.RUnlock()
	
	if patternCount == 0 {
		// Carrega padrões predefinidos se nenhum padrão estiver carregado
		rm.mu.Lock()
		err := rm.patternManager.LoadDefaultPatterns()
		patternCount = rm.patternManager.GetPatternCount()
		rm.mu.Unlock()
		
		if err != nil {
			return nil, fmt.Errorf("falha ao carregar padrões predefinidos: %w", err)
		}
		
		if patternCount == 0 {
			return nil, fmt.Errorf("nenhum padrão carregado")
		}
	}
	
	// Obtém os padrões do gerenciador de padrões
	compiledPatterns := rm.patternManager.GetCompiledPatterns()
	
	// Verifica extensões de arquivo excluídas
	for _, ext := range rm.excludedExtensions {
		if strings.HasSuffix(strings.ToLower(url), ext) {
			return nil, nil
		}
	}
	
	var secrets []Secret
	
	// Para cada padrão, procura no conteúdo
	for patternName, pattern := range compiledPatterns {
		// Tenta encontrar correspondências para este padrão
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) > 0 {
				// Extrai o valor real do segredo (primeiro grupo de captura ou correspondência completa)
				value := match[0]
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}
				
				// Ignora valores vazios e valores extremamente longos
				if len(value) < 4 || len(value) > 1000 {
					continue
				}
				
				// Validação básica de comprimento
				if len(value) < rm.minSecretLength || len(value) > rm.maxSecretLength {
					continue
				}
				
				// Cria um segredo com contexto
				context := extractContext(content, value)
				
				// Verifica exclusões específicas
				if rm.isExcluded(value, patternName, context) {
					continue
				}
				
				secret := Secret{
					Type:    patternName,
					Value:   value,
					Context: context,
					URL:     url,
				}
				secrets = append(secrets, secret)
			}
		}
	}
	
	return secrets, nil
}

// isExcluded verifica se um valor deve ser excluído com base em critérios específicos
func (rm *RegexManager) isExcluded(value, patternName, context string) bool {
	// Verifica padrões de código comuns que indicam falsos positivos
	if utils.HasCommonCodePattern(value) {
		return true
	}
	
	// Verifica palavras-chave de exclusão específicas do padrão
	compiledPatterns := rm.patternManager.GetCompiledPatterns()
	if pattern, exists := compiledPatterns[patternName]; exists {
		for _, keyword := range pattern.Config.KeywordExcludes {
			if strings.Contains(value, keyword) || strings.Contains(context, keyword) {
				return true
			}
		}
	}
	
	// Verifica se parece um caminho de arquivo
	if utils.IsLikelyFilePath(value) {
		return true
	}
	
	// Verifica se parece um tipo de conteúdo
	if utils.IsLikelyContentType(value) {
		return true
	}
	
	return false
}

// FindMatches encontra todas as correspondências regex no conteúdo e as retorna diretamente
// Isso é especialmente útil para escaneamento de arquivos locais
func (rm *RegexManager) FindMatches(content, url string) map[string][]string {
	// Obtém padrões do gerenciador de padrões
	allPatterns := rm.patternManager.GetCompiledPatterns()
	
	matches := make(map[string][]string)
	
	// Verifica a extensão do arquivo para determinar se algum tratamento especial é necessário
	isLocalFile := strings.HasPrefix(url, "file://")
	needsStrictFiltering := false
	
	// Conteúdo minificado precisa de filtragem mais estrita
	if len(content) > 5000 && strings.Count(content, "\n") < 10 {
		needsStrictFiltering = true
	}
	
	// Encontra correspondências para cada padrão
	for name, pattern := range allPatterns {
		// Para arquivos locais, use tanto FindAllString quanto FindAllStringSubmatch
		// para capturar todas as possibilidades
		
		// Primeiro, encontre todas as correspondências completas
		found := pattern.Regex.FindAllString(content, -1)
		
		// Em paralelo, encontre correspondências com grupos de captura
		var allMatches [][]string
		if isLocalFile || rm.isLocalFileMode {
			allMatches = pattern.Regex.FindAllStringSubmatch(content, -1)
		}
		
		// Contêiner para armazenar resultados exclusivos
		unique := make(map[string]bool)
		
		// Processa primeiro as correspondências do grupo de captura, se disponíveis
		if len(allMatches) > 0 {
			for _, matchGroup := range allMatches {
				if len(matchGroup) > 1 && matchGroup[1] != "" {
					// Use o primeiro grupo de captura como valor
					match := matchGroup[1]
					
					// Verifica se esta correspondência é válida
					if !rm.isExcluded(match, name, "") {
						// Arquivos locais usam validação especial
						isValid := true
						
						if isLocalFile || rm.isLocalFileMode {
							isValid = rm.isLocalFileSecretValid(match, name, content)
						} else if needsStrictFiltering {
							isValid = rm.isValidSecretStrict(match, name)
						}
						
						if isValid {
							unique[match] = true
						}
					}
				}
			}
		}
		
		// Também processa as correspondências completas para capturar padrões sem grupos
		for _, match := range found {
			if !rm.isExcluded(match, name, "") {
				isValid := true
				
				if isLocalFile || rm.isLocalFileMode {
					isValid = rm.isLocalFileSecretValid(match, name, content)
				} else if needsStrictFiltering {
					isValid = rm.isValidSecretStrict(match, name)
				}
				
				if isValid {
					unique[match] = true
				}
			}
		}
		
		// Converte para slice
		var uniqueMatches []string
		for match := range unique {
			// Para arquivos locais, reduz a filtragem ao mínimo
			if isLocalFile || rm.isLocalFileMode {
				// Já aplicamos a validação isLocalFileSecretValid,
				// então só verificamos o comprimento mínimo para evitar ruído
				if len(match) >= rm.minSecretLength {
					uniqueMatches = append(uniqueMatches, match)
				}
			} else {
				uniqueMatches = append(uniqueMatches, match)
			}
		}
		
		// Adiciona ao mapa de resultados
		if len(uniqueMatches) > 0 {
			matches[name] = uniqueMatches
		}
	}
	
	return matches
}

// isLocalFileSecretValid aplica validação especial para arquivos locais
func (rm *RegexManager) isLocalFileSecretValid(match, patternName, content string) bool {
	// Validação básica
	if len(match) < rm.minSecretLength || len(match) > rm.maxSecretLength {
		return false
	}
	
	// Verificação para padrões de código comuns que indicam falsos positivos
	if utils.HasCommonCodePattern(match) {
		return false
	}
	
	// Validação menos estrita para arquivos locais
	// Se contiver palavras-chave de exclusão comuns, rejeite
	commonExclusions := []string{
		"example", "sample", "test", "placeholder", "dummy",
		"http://", "https://", "localhost", "127.0.0.1",
		"node_modules", "charset=", "@example.com",
	}
	
	for _, exclusion := range commonExclusions {
		if strings.Contains(match, exclusion) {
			return false
		}
	}
	
	return true
}

// isValidSecretStrict aplica validação mais rigorosa para segredos em contextos minificados
func (rm *RegexManager) isValidSecretStrict(match, patternName string) bool {
	// Validação de comprimento mais rigorosa
	if len(match) < rm.minSecretLength*2 || len(match) > rm.maxSecretLength/2 {
		return false
	}
	
	// Verificação de padrões de código
	if utils.HasCommonCodePattern(match) {
		return false
	}
	
	return true
}

// SetLocalFileMode ativa ou desativa o modo de arquivo local
func (rm *RegexManager) SetLocalFileMode(enabled bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.isLocalFileMode = enabled
	rm.patternManager.SetLocalMode(enabled)
	
	// Ajusta limites de comprimento com base no modo
	if enabled {
		rm.minSecretLength = 4
		rm.maxSecretLength = 500
	} else {
		rm.minSecretLength = 5
		rm.maxSecretLength = 200
	}
}

// LoadPatternsFromFile carrega padrões de um arquivo para o RegexManager
func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
	// Por enquanto, esta é uma versão simplificada que delega ao PatternManager
	// para carregar os padrões padrão, já que a análise de arquivo não está implementada no novo sistema
	return rm.patternManager.LoadDefaultPatterns()
}

// LoadPredefinedPatterns carrega os padrões predefinidos
func (rm *RegexManager) LoadPredefinedPatterns() error {
	return rm.patternManager.LoadDefaultPatterns()
}

// GetPatternCount retorna o número de padrões
func (rm *RegexManager) GetPatternCount() int {
	return rm.patternManager.GetPatternCount()
}

// InjectDefaultPatternsDirectly é uma função legada que agora usa o novo sistema
func (rm *RegexManager) InjectDefaultPatternsDirectly() {
	rm.patternManager.LoadDefaultPatterns()
}

// Reset redefine o RegexManager para seu estado inicial
func (rm *RegexManager) Reset() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Redefine o PatternManager
	rm.patternManager.Reset()
	
	// Cria um novo PatternManager
	rm.patternManager = patterns.NewPatternManager()
	
	// Redefine outros campos
	rm.minSecretLength = 5
	rm.maxSecretLength = 200
	rm.isLocalFileMode = false
}

// CompleteReset realiza uma redefinição completa do RegexManager para o estado inicial
func (rm *RegexManager) CompleteReset() {
	rm.Reset()
}

