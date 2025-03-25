package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// RegexManager handles loading and applying regex patterns
type RegexManager struct {
	patterns map[string]*regexp.Regexp
}

// NewRegexManager creates a new regex manager
func NewRegexManager() *RegexManager {
	return &RegexManager{
		patterns: make(map[string]*regexp.Regexp),
	}
}

// LoadPatternsFromFile loads regex patterns from a file
func (rm *RegexManager) LoadPatternsFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if (err != nil) {
		return fmt.Errorf("failed to open regex file: %v", err)
	}
	defer file.Close()

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
			if strings.HasSuffix(patternRegex, ",") {
				patternRegex = patternRegex[:len(patternRegex)-1]
			}
			
			// Compile regex
			re, err := regexp.Compile(patternRegex)
			if err != nil {
				return fmt.Errorf("failed to compile regex '%s': %v", patternName, err)
			}
			
			rm.patterns[patternName] = re
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading regex file: %v", err)
	}

	if len(rm.patterns) == 0 {
		return fmt.Errorf("no regex patterns found in file")
	}

	return nil
}

// FindSecrets applies regex patterns to find secrets in content
func (rm *RegexManager) FindSecrets(content, url string) ([]Secret, error) {
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
			// Return line number (1-based) and the context
			return i + 1, strings.TrimSpace(line)
		}
	}
	return 0, ""
}
