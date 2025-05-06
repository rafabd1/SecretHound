package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/utils"
)

type RegexManager struct {
	patternManager     *patterns.PatternManager
	minSecretLength    int
	maxSecretLength    int
	isLocalFileMode    bool
	excludedExtensions []string
	mu                 sync.RWMutex
}

func NewRegexManager() *RegexManager {
	rm := &RegexManager{
		patternManager:     patterns.NewPatternManager(),
		minSecretLength:    5,
		maxSecretLength:    200,
		excludedExtensions: []string{".min.js", ".bundle.js", ".packed.js", ".compressed.js"},
		mu:                 sync.RWMutex{},
	}
	
	RegisterRegexManager(rm)
	
	return rm
}

/* 
   Searches for secrets in content using configured regex patterns
*/
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
	rm.mu.RLock()
	patternCount := rm.patternManager.GetPatternCount()
	rm.mu.RUnlock()
	
	if patternCount == 0 {
		rm.mu.Lock()
		err := rm.patternManager.LoadPatterns(nil, nil)
		patternCount = rm.patternManager.GetPatternCount()
		rm.mu.Unlock()
		
		if err != nil {
			return nil, fmt.Errorf("falha ao carregar padrões predefinidos: %w", err)
		}
		
		if patternCount == 0 {
			return nil, fmt.Errorf("nenhum padrão carregado")
		}
	}
	
	compiledPatterns := rm.patternManager.GetCompiledPatterns()
	
	for _, ext := range rm.excludedExtensions {
		if strings.HasSuffix(strings.ToLower(url), ext) {
			return nil, nil
		}
	}
	
	var secrets []Secret
	
	for patternName, pattern := range compiledPatterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) > 0 {
				value := match[0]
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}
				
				if len(value) < 4 || len(value) > 1000 {
					continue
				}
				
				if len(value) < rm.minSecretLength || len(value) > rm.maxSecretLength {
					continue
				}
				
				context := extractContext(content, value)
				
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

/* 
   Determines if a value should be excluded based on specific criteria
*/
func (rm *RegexManager) isExcluded(value, patternName, context string) bool {
	if utils.HasCommonCodePattern(value) {
		return true
	}
	
	compiledPatterns := rm.patternManager.GetCompiledPatterns()
	if pattern, exists := compiledPatterns[patternName]; exists {
		for _, keyword := range pattern.Config.KeywordExcludes {
			if strings.Contains(value, keyword) || strings.Contains(context, keyword) {
				return true
			}
		}
	}
	
	if utils.IsLikelyFilePath(value) {
		return true
	}
	
	if utils.IsLikelyContentType(value) {
		return true
	}
	
	return false
}

/*
   Finds all regex matches in content and returns them directly
   Useful for local file scanning
*/
func (rm *RegexManager) FindMatches(content, url string) map[string][]string {
	allPatterns := rm.patternManager.GetCompiledPatterns()
	
	matches := make(map[string][]string)
	
	isLocalFile := strings.HasPrefix(url, "file://")
	needsStrictFiltering := false
	
	if len(content) > 5000 && strings.Count(content, "\n") < 10 {
		needsStrictFiltering = true
	}
	
	for name, pattern := range allPatterns {
		found := pattern.Regex.FindAllString(content, -1)
		
		var allMatches [][]string
		if isLocalFile || rm.isLocalFileMode {
			allMatches = pattern.Regex.FindAllStringSubmatch(content, -1)
		}
		
		unique := make(map[string]bool)
		
		if len(allMatches) > 0 {
			for _, matchGroup := range allMatches {
				if len(matchGroup) > 1 && matchGroup[1] != "" {
					match := matchGroup[1]
					
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
			}
		}
		
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
		
		var uniqueMatches []string
		for match := range unique {
			if isLocalFile || rm.isLocalFileMode {
				if len(match) >= rm.minSecretLength {
					uniqueMatches = append(uniqueMatches, match)
				}
			} else {
				uniqueMatches = append(uniqueMatches, match)
			}
		}
		
		if len(uniqueMatches) > 0 {
			matches[name] = uniqueMatches
		}
	}
	
	return matches
}

/*
   Applies special validation for local files to reduce false positives
*/
func (rm *RegexManager) isLocalFileSecretValid(match, patternName, content string) bool {
	if len(match) < rm.minSecretLength || len(match) > rm.maxSecretLength {
		return false
	}
	
	if utils.HasCommonCodePattern(match) {
		return false
	}
	
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

/*
   Applies more rigorous validation for secrets in minified contexts
*/
func (rm *RegexManager) isValidSecretStrict(match, patternName string) bool {
	if len(match) < rm.minSecretLength*2 || len(match) > rm.maxSecretLength/2 {
		return false
	}
	
	if utils.HasCommonCodePattern(match) {
		return false
	}
	
	return true
}

func (rm *RegexManager) SetLocalFileMode(enabled bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.isLocalFileMode = enabled
	rm.patternManager.SetLocalMode(enabled)
	
	if enabled {
		rm.minSecretLength = 4
		rm.maxSecretLength = 500
	} else {
		rm.minSecretLength = 5
		rm.maxSecretLength = 200
	}
}

func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
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
	rm.minSecretLength = 5
	rm.maxSecretLength = 200
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
