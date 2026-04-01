package patterns

import (
	"embed"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed default_patterns.yaml
var embeddedPatternsFS embed.FS

type PatternConfig struct {
	Regex              string   `yaml:"regex"`
	Description        string   `yaml:"description"`
	Enabled            bool     `yaml:"enabled"`
	Category           string   `yaml:"category"`
	MinLength          int      `yaml:"minlength,omitempty"`
	MaxLength          int      `yaml:"maxlength,omitempty"`
	KeywordMatches     []string `yaml:"keywordmatches,omitempty"`
	KeywordExcludes    []string `yaml:"keywordexcludes,omitempty"`
	ExcludeRegexes     []string `yaml:"excluderegexes,omitempty"`
	RequiredContextAny []string `yaml:"requiredcontextany,omitempty"`
	ContextBoostAny    []string `yaml:"contextboostany,omitempty"`
	ContextPenaltyAny  []string `yaml:"contextpenaltyany,omitempty"`
	UseEntropy         bool     `yaml:"useentropy,omitempty"`
	MinEntropy         float64  `yaml:"minentropy,omitempty"`
	EntropyMinLength   int      `yaml:"entropyminlength,omitempty"`
}

type PatternDefinitions struct {
	Patterns map[string]PatternConfig `yaml:"patterns"`
}

var DefaultPatterns = loadEmbeddedPatterns()

type CompiledPattern struct {
	Name                   string
	Description            string
	Regex                  *regexp.Regexp
	CompiledExcludeRegexes []*regexp.Regexp
	Config                 PatternConfig
}

type PatternManager struct {
	compiledPatterns   map[string]*CompiledPattern
	exclusionPatterns  []*regexp.Regexp
	specificExclusions map[string][]*regexp.Regexp
	localModeEnabled   bool
	definitions        *PatternDefinitions
	mu                 sync.RWMutex
}

func loadEmbeddedPatterns() *PatternDefinitions {
	content, err := embeddedPatternsFS.ReadFile("default_patterns.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] failed to read embedded patterns: %v\n", err)
		return &PatternDefinitions{Patterns: map[string]PatternConfig{}}
	}

	defs, err := parsePatternDefinitions(content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] failed to parse embedded patterns: %v\n", err)
		return &PatternDefinitions{Patterns: map[string]PatternConfig{}}
	}

	return defs
}

func parsePatternDefinitions(content []byte) (*PatternDefinitions, error) {
	defs := &PatternDefinitions{}
	if err := yaml.Unmarshal(content, defs); err != nil {
		return nil, err
	}

	if defs.Patterns == nil {
		defs.Patterns = map[string]PatternConfig{}
	}

	return defs, nil
}

func cloneDefinitions(src *PatternDefinitions) *PatternDefinitions {
	if src == nil {
		return &PatternDefinitions{Patterns: map[string]PatternConfig{}}
	}

	copied := &PatternDefinitions{Patterns: make(map[string]PatternConfig, len(src.Patterns))}
	for name, cfg := range src.Patterns {
		copied.Patterns[name] = cfg
	}

	return copied
}

func NewPatternManager() *PatternManager {
	pm := &PatternManager{
		compiledPatterns:   make(map[string]*CompiledPattern),
		exclusionPatterns:  make([]*regexp.Regexp, 0),
		specificExclusions: make(map[string][]*regexp.Regexp),
		definitions:        cloneDefinitions(DefaultPatterns),
	}

	_ = pm.LoadPatterns(nil, nil)
	return pm
}

func (pm *PatternManager) LoadDefinitionsFromFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed reading patterns file %s: %w", filePath, err)
	}

	defs, err := parsePatternDefinitions(content)
	if err != nil {
		return fmt.Errorf("failed parsing patterns file %s: %w", filePath, err)
	}

	pm.mu.Lock()
	pm.definitions = defs
	pm.mu.Unlock()

	return nil
}

func (pm *PatternManager) LoadPatterns(includeCategories, excludeCategories []string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.compiledPatterns = make(map[string]*CompiledPattern)

	includeMap := make(map[string]bool)
	for _, cat := range includeCategories {
		includeMap[strings.ToLower(cat)] = true
	}

	excludeMap := make(map[string]bool)
	for _, cat := range excludeCategories {
		excludeMap[strings.ToLower(cat)] = true
	}

	useInclude := len(includeCategories) > 0
	useExclude := len(excludeCategories) > 0

	for name, config := range pm.definitions.Patterns {
		categoryLower := strings.ToLower(config.Category)
		isIncluded := useInclude && includeMap[categoryLower]
		isExcluded := useExclude && excludeMap[categoryLower]
		isEnabledByDefault := config.Enabled

		loadPattern := false
		if isIncluded {
			loadPattern = true
		} else if !useInclude && !isExcluded && isEnabledByDefault {
			loadPattern = true
		}

		if !loadPattern {
			continue
		}

		re, err := regexp.Compile(config.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to compile regex for pattern '%s': %v\nRegex: %s\n", name, err, config.Regex)
			continue
		}

		pm.compiledPatterns[name] = &CompiledPattern{
			Name:                   name,
			Description:            config.Description,
			Regex:                  re,
			CompiledExcludeRegexes: compileExcludeRegexes(config.ExcludeRegexes),
			Config:                 config,
		}
	}

	criticalExclusions := []string{"example", "sample", "test", "demo", "function(", "return"}
	pm.exclusionPatterns = make([]*regexp.Regexp, 0, len(criticalExclusions))
	for _, exclusion := range criticalExclusions {
		re, err := regexp.Compile(regexp.QuoteMeta(exclusion))
		if err != nil {
			continue
		}
		pm.exclusionPatterns = append(pm.exclusionPatterns, re)
	}

	return nil
}

func (pm *PatternManager) SetLocalMode(enabled bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.localModeEnabled = enabled
}

func (pm *PatternManager) IsLocalModeEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.localModeEnabled
}

func (pm *PatternManager) GetPatternCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.compiledPatterns)
}

func (pm *PatternManager) GetCompiledPatterns() map[string]*CompiledPattern {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	patterns := make(map[string]*CompiledPattern, len(pm.compiledPatterns))
	for k, v := range pm.compiledPatterns {
		patterns[k] = v
	}

	return patterns
}

func (pm *PatternManager) GetDefinitions() *PatternDefinitions {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return cloneDefinitions(pm.definitions)
}

func (pm *PatternManager) AddPattern(name, regex, description string) error {
	re, err := regexp.Compile(regex)
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.compiledPatterns[name] = &CompiledPattern{
		Name:                   name,
		Description:            description,
		Regex:                  re,
		CompiledExcludeRegexes: []*regexp.Regexp{},
		Config: PatternConfig{
			Regex:       regex,
			Description: description,
			Enabled:     true,
			MinLength:   8,
			MaxLength:   500,
		},
	}

	pm.definitions.Patterns[name] = pm.compiledPatterns[name].Config
	return nil
}

func compileExcludeRegexes(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, raw := range patterns {
		re, err := regexp.Compile(raw)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func (pm *PatternManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.compiledPatterns = make(map[string]*CompiledPattern)
	pm.exclusionPatterns = make([]*regexp.Regexp, 0)
	pm.specificExclusions = make(map[string][]*regexp.Regexp)
	pm.localModeEnabled = false
	pm.definitions = cloneDefinitions(DefaultPatterns)
}
