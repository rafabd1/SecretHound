package detector

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/pipeline"
	"github.com/rafabd1/SecretHound/output"
)

type benchmarkManifest struct {
	Cases []benchmarkCase `json:"cases"`
}

type benchmarkCase struct {
	ID            string `json:"id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	Value         string `json:"value"`
	ExpectedType  string `json:"expected_type"`
	ExpectedStage string `json:"expected_stage"`
	EntropyGate   string `json:"entropy_gate"`
	ExpectedCount int    `json:"expected_count,omitempty"`
}

type benchmarkFinding struct {
	Type  string
	Value string
}

func TestSemanticBenchmarkCorpusDetectionStages(t *testing.T) {
	benchmarkRoot := filepath.Join("..", "..", "dev", "filesTest", "semantic_benchmark")
	manifest := loadBenchmarkManifest(t, filepath.Join(benchmarkRoot, "manifest.json"))

	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns(nil, nil); err != nil {
		t.Fatal(err)
	}
	detector := NewDetector(patternManager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		ContextSize:   100,
		MinConfidence: 0.5,
	})

	detectedFindings := make(map[string]map[benchmarkFinding]bool)
	detectedCounts := make(map[string]map[benchmarkFinding]int)
	corpusRoot := filepath.Join(benchmarkRoot, "corpus")
	err := filepath.WalkDir(corpusRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(corpusRoot, path)
		if err != nil {
			return err
		}
		findings, err := detector.DetectSecrets(string(content), "file://"+filepath.ToSlash(path))
		if err != nil {
			return err
		}
		findings = pipeline.ResolvePatternCollisions(patternManager, findings)
		for _, finding := range findings {
			key := filepath.ToSlash(relative) + ":" + stringLine(finding.Line)
			if detectedFindings[key] == nil {
				detectedFindings[key] = make(map[benchmarkFinding]bool)
				detectedCounts[key] = make(map[benchmarkFinding]int)
			}
			candidate := benchmarkFinding{Type: finding.Type, Value: finding.Value}
			detectedFindings[key][candidate] = true
			detectedCounts[key][candidate]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedLocations := make(map[string]bool)
	expectedFindings := make(map[string]map[benchmarkFinding]bool)
	for _, item := range manifest.Cases {
		key := filepath.ToSlash(item.File) + ":" + stringLine(item.Line)
		expectedLocations[key] = true
		if item.ExpectedStage == "semantic" {
			if item.ExpectedType == "" {
				t.Errorf("%s has no expected_type", item.ID)
			}
			if expectedFindings[key] == nil {
				expectedFindings[key] = make(map[benchmarkFinding]bool)
			}
			expectedFindings[key][benchmarkFinding{Type: item.ExpectedType, Value: item.Value}] = true
		}
		matched := detectedFindings[key][benchmarkFinding{Type: item.ExpectedType, Value: item.Value}]
		if item.ExpectedStage == "semantic" && !matched {
			t.Errorf("%s did not reach semantic stage as %s", item.ID, item.ExpectedType)
		}
		if item.ExpectedStage == "semantic" && matched {
			expectedCount := item.ExpectedCount
			if expectedCount <= 0 {
				expectedCount = 1
			}
			candidate := benchmarkFinding{Type: item.ExpectedType, Value: item.Value}
			if actual := detectedCounts[key][candidate]; actual != expectedCount {
				t.Errorf("%s produced %d occurrences, expected %d", item.ID, actual, expectedCount)
			}
		}
		if item.ExpectedStage == "heuristic_reject" && benchmarkValueDetected(detectedFindings[key], item.Value) {
			t.Errorf("%s produced a finding, expected heuristic rejection", item.ID)
		}
	}

	for key, findings := range detectedFindings {
		if !expectedLocations[key] {
			t.Errorf("unexpected semantic-corpus finding at %s", key)
			continue
		}
		for finding := range findings {
			if !expectedFindings[key][finding] {
				t.Errorf("unexpected semantic-corpus finding at %s: type=%s value=%q", key, finding.Type, finding.Value)
			}
		}
	}
}

func TestPIIBenchmarkCorpusDetectionStages(t *testing.T) {
	benchmarkRoot := filepath.Join("..", "..", "dev", "filesTest", "pii_benchmark")
	manifest := loadBenchmarkManifest(t, filepath.Join(benchmarkRoot, "manifest.json"))

	patternManager := patterns.NewPatternManager()
	if err := patternManager.LoadPatterns([]string{"pii"}, nil); err != nil {
		t.Fatal(err)
	}
	detector := NewDetector(patternManager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		ContextSize:   100,
		MinConfidence: 0.5,
	})

	detectedFindings := make(map[string]map[benchmarkFinding]bool)
	detectedCounts := make(map[string]map[benchmarkFinding]int)
	corpusRoot := filepath.Join(benchmarkRoot, "corpus")
	err := filepath.WalkDir(corpusRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(corpusRoot, path)
		if err != nil {
			return err
		}
		findings, err := detector.DetectSecrets(string(content), "file://"+filepath.ToSlash(path))
		if err != nil {
			return err
		}
		for _, finding := range findings {
			key := filepath.ToSlash(relative) + ":" + stringLine(finding.Line)
			if detectedFindings[key] == nil {
				detectedFindings[key] = make(map[benchmarkFinding]bool)
				detectedCounts[key] = make(map[benchmarkFinding]int)
			}
			candidate := benchmarkFinding{Type: finding.Type, Value: finding.Value}
			detectedFindings[key][candidate] = true
			detectedCounts[key][candidate]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedLocations := make(map[string]bool)
	expectedFindings := make(map[string]map[benchmarkFinding]bool)
	for _, item := range manifest.Cases {
		key := filepath.ToSlash(item.File) + ":" + stringLine(item.Line)
		expectedLocations[key] = true
		if item.ExpectedStage == "semantic" {
			if item.ExpectedType == "" {
				t.Errorf("%s has no expected_type", item.ID)
			}
			if expectedFindings[key] == nil {
				expectedFindings[key] = make(map[benchmarkFinding]bool)
			}
			expectedFindings[key][benchmarkFinding{Type: item.ExpectedType, Value: item.Value}] = true
		}
		matched := detectedFindings[key][benchmarkFinding{Type: item.ExpectedType, Value: item.Value}]
		if item.ExpectedStage == "semantic" && !matched {
			t.Errorf("%s did not reach semantic stage as %s", item.ID, item.ExpectedType)
		}
		if item.ExpectedStage == "semantic" && matched {
			expectedCount := item.ExpectedCount
			if expectedCount <= 0 {
				expectedCount = 1
			}
			candidate := benchmarkFinding{Type: item.ExpectedType, Value: item.Value}
			if actual := detectedCounts[key][candidate]; actual != expectedCount {
				t.Errorf("%s produced %d occurrences, expected %d", item.ID, actual, expectedCount)
			}
		}
		if item.ExpectedStage == "heuristic_reject" && benchmarkValueDetected(detectedFindings[key], item.Value) {
			t.Errorf("%s produced a finding, expected heuristic rejection", item.ID)
		}
	}

	for key, findings := range detectedFindings {
		if !expectedLocations[key] {
			t.Errorf("unexpected PII finding at %s", key)
			continue
		}
		for finding := range findings {
			if !expectedFindings[key][finding] {
				t.Errorf("unexpected PII finding at %s: type=%s value=%q", key, finding.Type, finding.Value)
			}
		}
	}
}

func benchmarkValueDetected(findings map[benchmarkFinding]bool, value string) bool {
	for finding := range findings {
		if finding.Value == value {
			return true
		}
	}
	return false
}

func TestSemanticBenchmarkCorpusEntropyBands(t *testing.T) {
	manifest := loadBenchmarkManifest(t, filepath.Join("..", "..", "dev", "filesTest", "semantic_benchmark", "manifest.json"))
	for _, item := range manifest.Cases {
		entropy := testEntropy(item.Value)
		switch item.EntropyGate {
		case "pass":
			if entropy < 3.5 {
				t.Errorf("%s entropy %.3f is below pass band", item.ID, entropy)
			}
		case "fail":
			if entropy >= 3.0 {
				t.Errorf("%s entropy %.3f is above fail band", item.ID, entropy)
			}
		}
	}
}

func loadBenchmarkManifest(t *testing.T, path string) benchmarkManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest benchmarkManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func testEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, character := range value {
		counts[character]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func stringLine(line int) string {
	if line == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for line > 0 {
		digits = append(digits, byte('0'+line%10))
		line /= 10
	}
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}
	return string(digits)
}
