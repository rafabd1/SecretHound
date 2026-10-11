package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rafabd1/SecretHound/core/detector"
	"github.com/rafabd1/SecretHound/core/patterns"
)

type RegexManager struct {
	patternManager  *patterns.PatternManager
	isLocalFileMode bool
	mu              sync.RWMutex
}

func NewRegexManager() *RegexManager {
	rm := &RegexManager{
		patternManager: patterns.NewPatternManager(),
		mu:             sync.RWMutex{},
	}

	RegisterRegexManager(rm)

	return rm
}

/*
Searches for secrets in content using configured regex patterns
*/
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
	rm.mu.RLock()
	patternManager := rm.patternManager
	localMode := rm.isLocalFileMode
	rm.mu.RUnlock()

	patternCount := patternManager.GetPatternCount()

	if patternCount == 0 {
		rm.mu.Lock()
		err := patternManager.LoadPatterns(nil, nil)
		patternCount = patternManager.GetPatternCount()
		rm.mu.Unlock()

		if err != nil {
			return nil, fmt.Errorf("falha ao carregar padrões predefinidos: %w", err)
		}

		if patternCount == 0 {
			return nil, fmt.Errorf("nenhum padrão carregado")
		}
	}

	return detector.ScanContent(patternManager, detector.Config{
		LocalFileMode: localMode || strings.HasPrefix(url, "file://"),
	}, content, url)
}

/*
Finds all regex matches in content and returns them directly
Useful for local file scanning
*/
func (rm *RegexManager) FindMatches(content, url string) map[string][]string {
	matches := make(map[string][]string)
	findings, err := rm.FindSecrets(content, url)
	if err != nil {
		return matches
	}

	seen := make(map[string]map[string]bool)
	for _, finding := range findings {
		if seen[finding.Type] == nil {
			seen[finding.Type] = make(map[string]bool)
		}
		if seen[finding.Type][finding.Value] {
			continue
		}
		seen[finding.Type][finding.Value] = true
		matches[finding.Type] = append(matches[finding.Type], finding.Value)
	}
	return matches
}

func (rm *RegexManager) SetLocalFileMode(enabled bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.isLocalFileMode = enabled
	rm.patternManager.SetLocalMode(enabled)
}

func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
	if err := rm.patternManager.LoadDefinitionsFromFile(filePath); err != nil {
		return err
	}
	return rm.patternManager.LoadPatterns(nil, nil)
}

func (rm *RegexManager) LoadPredefinedPatterns() error {
	return rm.patternManager.LoadPatterns(nil, nil)
}

func (rm *RegexManager) GetPatternCount() int {
	return rm.patternManager.GetPatternCount()
}

func (rm *RegexManager) InjectDefaultPatternsDirectly() {
	_ = rm.patternManager.LoadPatterns(nil, nil)
}

func (rm *RegexManager) Reset() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.patternManager.Reset()
	rm.patternManager = patterns.NewPatternManager()
	rm.isLocalFileMode = false
}

func (rm *RegexManager) CompleteReset() {
	rm.Reset()
}

// Add a setter method for the pattern manager
func (rm *RegexManager) SetPatternManager(pm *patterns.PatternManager) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.patternManager = pm
}
