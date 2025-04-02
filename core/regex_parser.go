package core

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// LoadPredefinedPatterns carrega padrões predefinidos para o RegexManager
func (rm *RegexManager) LoadPredefinedPatterns() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Limpa padrões existentes
	rm.patterns = make(map[string]*regexp.Regexp)
	rm.exclusionPatterns = make([]*regexp.Regexp, 0)
	rm.patternExclusions = make(map[string][]*regexp.Regexp)

	// Compila e adiciona cada padrão predefinido de RegexPatterns
	for name, pattern := range RegexPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex pattern '%s': %v", name, err)
		}
		rm.patterns[name] = re
	}

	// Compila e adiciona padrões de exclusão de ExclusionPatterns
	for _, pattern := range ExclusionPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile exclude pattern: %v", err)
		}
		rm.exclusionPatterns = append(rm.exclusionPatterns, re)
	}

	// Compila e adiciona exclusões específicas por padrão
	for patternName, exclusions := range SpecificExclusions {
		var compiledExclusions []*regexp.Regexp
		for _, exclusion := range exclusions {
			re, err := regexp.Compile(exclusion)
			if err != nil {
				return fmt.Errorf("failed to compile specific exclusion pattern for '%s': %v", patternName, err)
			}
			compiledExclusions = append(compiledExclusions, re)
		}
		rm.patternExclusions[patternName] = compiledExclusions
	}

	return nil
}

// isValidSecretStrict applies stricter validation for secrets
func (rm *RegexManager) isValidSecretStrict(value string, patternType string) bool {
	if !rm.isValidSecret(value, patternType) {
		return false
	}

	if len(value) < rm.minSecretLength*2 || len(value) > rm.maxSecretLength/2 {
		return false
	}

	// Verify if the value contains minified code patterns
	codeChars := []string{"{", "}", ";", "&&", "||", "==", "!=", "=>", "+=", "-="}
	for _, char := range codeChars {
		if strings.Contains(value, char) {
			return false
		}
	}

	return true
}

// isExcludedByContextStrict applies stricter exclusion checks based on context
func (rm *RegexManager) isExcludedByContextStrict(context string, patternName string) bool {
	// Aplicar primeiro verificação básica
	if rm.isExcludedByContext(context) {
		return true
	}

	if exclusions, exists := rm.patternExclusions[patternName]; exists {
		for _, re := range exclusions {
			if re.MatchString(context) {
				return true
			}
		}
	}

	return false
}

// ParsePatternsFromFile parses regex patterns from a file
func ParsePatternsFromFile(filePath string) (map[string]string, []string, map[string][]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open regex file: %w", err)
	}
	defer f.Close()

	patterns := make(map[string]string)
	var excludePatterns []string
	specificExclusions := make(map[string][]string)
	
	scanner := bufio.NewScanner(f)

	// Read line by line
	inRegexBlock := false
	inExcludeBlock := false
	inSpecificExclusionsBlock := false
	var patternBlock strings.Builder
	var excludeBlock strings.Builder
	var specificExclusionsBlock strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		
		// Check for the start of regex patterns
		if strings.Contains(line, "REGEX_PATTERNS") && strings.Contains(line, "{") {
			inRegexBlock = true
			patternBlock.WriteString(line)
			continue
		}

		// Check for the start of exclude patterns
		if strings.Contains(line, "EXCLUSION_PATTERNS") && strings.Contains(line, "[") {
			inExcludeBlock = true
			excludeBlock.WriteString(line)
			continue
		}

		// Check for the start of specific exclusions
		if strings.Contains(line, "SPECIFIC_EXCLUSIONS") && strings.Contains(line, "{") {
			inSpecificExclusionsBlock = true
			specificExclusionsBlock.WriteString(line)
			continue
		}

		// Collect regex pattern lines
		if inRegexBlock {
			patternBlock.WriteString(line)

			// Check for the end of the regex block
			if strings.Contains(line, "}") && !strings.Contains(line, "{") {
				inRegexBlock = false
				regexStr := patternBlock.String()
				parsePatterns, err := parsePatternBlock(regexStr)
				if err != nil {
					return nil, nil, nil, err
				}
				for k, v := range parsePatterns {
					patterns[k] = v
				}
			}
		}

		// Collect exclude pattern lines
		if inExcludeBlock {
			excludeBlock.WriteString(line)

			// Check for the end of the exclude block
			if strings.Contains(line, "]") && !strings.Contains(line, "[") {
				inExcludeBlock = false
				excludeStr := excludeBlock.String()
				excludes, err := parseExcludeBlock(excludeStr)
				if err != nil {
					return nil, nil, nil, err
				}
				excludePatterns = append(excludePatterns, excludes...)
			}
		}

		// Collect specific exclusions lines
		if inSpecificExclusionsBlock {
			specificExclusionsBlock.WriteString(line)

			// Check for the end of the block
			if strings.Contains(line, "}") && 
			   strings.Count(specificExclusionsBlock.String(), "{") == strings.Count(specificExclusionsBlock.String(), "}") {
				inSpecificExclusionsBlock = false
				specificExclusionsStr := specificExclusionsBlock.String()
				parsedSpecificExclusions, err := parseSpecificExclusionsBlock(specificExclusionsStr)
				if err != nil {
					return nil, nil, nil, err
				}
				for k, v := range parsedSpecificExclusions {
					specificExclusions[k] = v
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("error reading regex file: %w", err)
	}

	// If no patterns were found, try a simpler parsing approach
	if len(patterns) == 0 {
		// Reset scanner to beginning of file
		_, err := f.Seek(0, 0)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to reset file position: %w", err)
		}
		scanner = bufio.NewScanner(f)
		patterns, excludePatterns, specificExclusions = parseSimpleFormat(scanner)
	}

	return patterns, excludePatterns, specificExclusions, nil
}

// parsePatternBlock parses a regex pattern block
func parsePatternBlock(block string) (map[string]string, error) {
	patterns := make(map[string]string)
	
	// Extract the contents of the REGEX_PATTERNS = { ... } block
	regex := regexp.MustCompile(`REGEX_PATTERNS[^{]*{([^}]*)}`)
	match := regex.FindStringSubmatch(block)
	if len(match) < 2 {
		return nil, fmt.Errorf("invalid regex pattern format")
	}
	
	// Extract key-value pairs
	pairRegex := regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]+)",?`)
	pairs := pairRegex.FindAllStringSubmatch(match[1], -1)
	
	// If no patterns found with double quotes, try with single quotes
	if len(pairs) == 0 {
		pairRegex = regexp.MustCompile(`'([^']+)'\s*:\s*'([^']+)',?`)
		pairs = pairRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// If still no patterns found, try with a more lenient regex
	if len(pairs) == 0 {
		pairRegex = regexp.MustCompile(`["']?([^"':,]+)["']?\s*:\s*["']([^"']+)["'],?`)
		pairs = pairRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// If still no patterns found, try with backtick quotes for regex patterns
	if len(pairs) == 0 {
		pairRegex = regexp.MustCompile(`["']([^"':,]+)["']\s*:\s*` + "`([^`]+)`" + `,?`)
		pairs = pairRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// Process each pattern
	for _, pair := range pairs {
		if len(pair) >= 3 {
			patterns[pair[1]] = pair[2]
		}
	}
	
	return patterns, nil
}

// parseExcludeBlock parses an exclude pattern block
func parseExcludeBlock(block string) ([]string, error) {
	var excludePatterns []string
	
	// Extract the contents of the EXCLUSION_PATTERNS = [ ... ] block
	regex := regexp.MustCompile(`EXCLUSION_PATTERNS[^[]*\[(.*?)\]`)
	match := regex.FindStringSubmatch(block)
	if len(match) < 2 {
		return nil, fmt.Errorf("invalid exclusion pattern format")
	}
	
	// Extract patterns
	patternRegex := regexp.MustCompile(`"([^"]+)",?`)
	patterns := patternRegex.FindAllStringSubmatch(match[1], -1)
	
	// If no patterns found with double quotes, try with single quotes
	if len(patterns) == 0 {
		patternRegex = regexp.MustCompile(`'([^']+)',?`)
		patterns = patternRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// If still no patterns found, try with a more lenient regex
	if len(patterns) == 0 {
		patternRegex = regexp.MustCompile(`["']([^"']+)["'],?`)
		patterns = patternRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// If still no patterns found, try with backtick quotes
	if len(patterns) == 0 {
		patternRegex = regexp.MustCompile("`([^`]+)`" + `,?`)
		patterns = patternRegex.FindAllStringSubmatch(match[1], -1)
	}
	
	// Process each pattern
	for _, pattern := range patterns {
		if len(pattern) >= 2 {
			excludePatterns = append(excludePatterns, pattern[1])
		}
	}
	
	return excludePatterns, nil
}

// parseSpecificExclusionsBlock parses the specific exclusions block
func parseSpecificExclusionsBlock(block string) (map[string][]string, error) {
	specificExclusions := make(map[string][]string)
	
	// Extract the contents between braces
	regex := regexp.MustCompile(`SPECIFIC_EXCLUSIONS[^{]*{(.*)}`)
	match := regex.FindStringSubmatch(block)
	if len(match) < 2 {
		return nil, fmt.Errorf("invalid specific exclusions format")
	}
	
	// Extract each pattern-exclusions pair
	content := match[1]
	
	// Split by pattern names (looking for "pattern_name": [...], pattern)
	patternBlockRegex := regexp.MustCompile(`["']([^"']+)["']\s*:\s*\[(.*?)\],?`)
	patternBlocks := patternBlockRegex.FindAllStringSubmatch(content, -1)
	
	for _, patternBlock := range patternBlocks {
		if len(patternBlock) >= 3 {
			patternName := patternBlock[1]
			exclusionsContent := patternBlock[2]
			
			// Extract exclusions from the block
			exclusionRegex := regexp.MustCompile(`["']([^"']+)["'],?`)
			exclusions := exclusionRegex.FindAllStringSubmatch(exclusionsContent, -1)
			
			var patternExclusions []string
			for _, exclusion := range exclusions {
				if len(exclusion) >= 2 {
					patternExclusions = append(patternExclusions, exclusion[1])
				}
			}
			
			specificExclusions[patternName] = patternExclusions
		}
	}
	
	return specificExclusions, nil
}

// parseSimpleFormat parses a simple name=pattern format
func parseSimpleFormat(scanner *bufio.Scanner) (map[string]string, []string, map[string][]string) {
	patterns := make(map[string]string)
	var excludePatterns []string
	specificExclusions := make(map[string][]string)
	
	inExcludeSection := false
	inSpecificExclusionSection := false
	currentPattern := ""
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		
		// Check for section markers
		if strings.Contains(line, "[EXCLUDE]") {
			inExcludeSection = true
			inSpecificExclusionSection = false
			continue
		}
		
		if strings.Contains(line, "[PATTERNS]") {
			inExcludeSection = false
			inSpecificExclusionSection = false
			continue
		}
		
		if strings.Contains(line, "[SPECIFIC_EXCLUSIONS]") {
			inExcludeSection = false
			inSpecificExclusionSection = true
			continue
		}
		
		// Process line based on section
		if inExcludeSection {
			// This is an exclude pattern
			pattern := strings.TrimSpace(line)
			if pattern != "" {
				excludePatterns = append(excludePatterns, pattern)
			}
		} else if inSpecificExclusionSection {
			// Format should be "pattern_name: exclusion_pattern"
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				patternName := strings.TrimSpace(parts[0])
				exclusion := strings.TrimSpace(parts[1])
				
				if exclusion != "" {
					if currentPattern != patternName {
						currentPattern = patternName
					}
					
					if _, exists := specificExclusions[currentPattern]; !exists {
						specificExclusions[currentPattern] = []string{}
					}
					
					specificExclusions[currentPattern] = append(specificExclusions[currentPattern], exclusion)
				}
			}
		} else {
			// This is a regular pattern
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				pattern := strings.TrimSpace(parts[1])
				if name != "" && pattern != "" {
					patterns[name] = pattern
				}
			}
		}
	}
	
	return patterns, excludePatterns, specificExclusions
}

