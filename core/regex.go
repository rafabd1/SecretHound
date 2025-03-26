package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	
	"github.com/secrethound/utils"
)

// RegexManager handles loading and applying regex patterns
type RegexManager struct {
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

// NewRegexManager creates a new regex manager
func NewRegexManager() *RegexManager {
	return &RegexManager{
		patterns: make(map[string]*regexp.Regexp),
		mu:       sync.RWMutex{},
	}
}

// LoadPatternsFromFile loads regex patterns from a file
func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
	// First check if the file exists
	if !utils.FileExists(filePath) {
		return fmt.Errorf("regex file not found: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open regex file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var inPatternSection bool
	
	// Create a temporary map to avoid partial updates in case of errors
	tempPatterns := make(map[string]*regexp.Regexp)
	
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
			
			// Compile regex
			re, err := regexp.Compile(patternRegex)
			if err != nil {
				return fmt.Errorf("failed to compile regex '%s': %v", patternName, err)
			}
			
			tempPatterns[patternName] = re
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading regex file: %v", err)
	}

	if len(tempPatterns) == 0 {
		return fmt.Errorf("no regex patterns found in file")
	}

	// Update the patterns map atomically
	rm.mu.Lock()
	rm.patterns = tempPatterns
	rm.mu.Unlock()

	return nil
}

// AddPattern adds a single regex pattern to the manager
func (rm *RegexManager) AddPattern(name, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex '%s': %v", name, err)
	}
	
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.patterns[name] = re
	return nil
}

// RemovePattern removes a pattern from the manager
func (rm *RegexManager) RemovePattern(name string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	delete(rm.patterns, name)
}

// GetPatternNames returns the names of all patterns
func (rm *RegexManager) GetPatternNames() []string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	names := make([]string, 0, len(rm.patterns))
	for name := range rm.patterns {
		names = append(names, name)
	}
	
	return names
}

// GetPatternCount returns the number of patterns
func (rm *RegexManager) GetPatternCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	return len(rm.patterns)
}

// FindSecrets applies regex patterns to find secrets in content
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	var secrets []Secret
	
	// Split content into lines for better context reporting
	lines := strings.Split(content, "\n")
	
	for patternName, re := range rm.patterns {
		// Find all matches in the entire content
		matches := re.FindAllStringIndex(content, -1)
		
		for _, match := range matches {
			// Extract matched string
			matchedText := content[match[0]:match[1]]
			
			// Find the line number and context
			lineNum, context := rm.findLineAndContext(lines, matchedText)
			
			secret := Secret{
				Type:    patternName,
				Value:   matchedText,
				URL:     url,
				Line:    lineNum,
				Context: context,
			}
			
			secrets = append(secrets, secret)
		}
	}
	
	return secrets, nil
}

// findLineAndContext finds the line number and context of a matched string
func (rm *RegexManager) findLineAndContext(lines []string, match string) (int, string) {
	for i, line := range lines {
		if strings.Contains(line, match) {
			// Get context (the line itself, truncated if very long)
			context := line
			if len(context) > 200 {
				// Find the position of the match in the line
				pos := strings.Index(line, match)
				start := pos - 30
				if start < 0 {
					start = 0
				}
				end := pos + len(match) + 30
				if end > len(line) {
					end = len(line)
				}
				context = "..." + line[start:end] + "..."
			}
			
			// Return line number (1-based) and the context
			return i + 1, strings.TrimSpace(context)
		}
	}
	return 0, ""
}

// FindAllMatches finds all matches for a specific pattern in content
func (rm *RegexManager) FindAllMatches(patternName, content string) ([]string, error) {
	rm.mu.RLock()
	re, exists := rm.patterns[patternName]
	rm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("pattern '%s' does not exist", patternName)
	}
	
	matches := re.FindAllString(content, -1)
	return matches, nil
}

// ClearPatterns removes all patterns from the manager
func (rm *RegexManager) ClearPatterns() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.patterns = make(map[string]*regexp.Regexp)
}

// HasPattern checks if a pattern exists
func (rm *RegexManager) HasPattern(name string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	_, exists := rm.patterns[name]
	return exists
}
