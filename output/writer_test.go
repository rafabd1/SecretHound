package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterPersistsSemanticMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	writer, err := NewWriter(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	err = writer.WriteFinding("source", SecretFindingData{
		Type:           "api_key_assignment",
		Risk:           "high",
		Value:          "synthetic-value",
		SourceURL:      "file://config.js",
		Line:           7,
		Context:        []string{"API_KEY=synthetic-value"},
		Occurrences:    1,
		Confidence:     0.81,
		ReviewPriority: "low",
		FilterStatus:   "likely_false_positive",
		FilterScore:    0.97,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var findings []SecretFindingData
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].FilterStatus != "likely_false_positive" || findings[0].ReviewPriority != "low" || findings[0].Line != 7 {
		t.Fatalf("unexpected output: %+v", findings)
	}
}

func TestWriterIncludesSemanticMetadataInTextAndCSV(t *testing.T) {
	for _, extension := range []string{".txt", ".csv"} {
		t.Run(extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings"+extension)
			writer, err := NewWriter(path, false, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteFinding("source", SecretFindingData{
				Type:           "token",
				Risk:           "high",
				Value:          "synthetic",
				SourceURL:      "file://a.js",
				ReviewPriority: "low",
				FilterStatus:   "likely_false_positive",
				FilterScore:    0.95,
			}); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			if !strings.Contains(text, "likely_false_positive") || !strings.Contains(text, "low") {
				t.Fatalf("semantic metadata missing from %s output: %s", extension, text)
			}
		})
	}
}

func TestWriterIncludesByteOffsetInTextAndCSV(t *testing.T) {
	for _, extension := range []string{".txt", ".csv"} {
		t.Run(extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings"+extension)
			writer, err := NewWriter(path, false, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteFinding("source", SecretFindingData{
				Type:       "token",
				Value:      "synthetic",
				SourceURL:  "file://a.js",
				Line:       3,
				ByteOffset: 27,
			}); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			if extension == ".csv" {
				if !strings.Contains(text, "Line,ByteOffset,Occurrences") || !strings.Contains(text, ",3,27,1,") {
					t.Fatalf("byte offset missing from CSV output: %s", text)
				}
			} else if !strings.Contains(text, "Byte offset: 27") {
				t.Fatalf("byte offset missing from TXT output: %s", text)
			}
		})
	}
}

func TestWriterGroupedCSVIncludesHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.csv")
	writer, err := NewWriter(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteFinding("source", SecretFindingData{
		Type:      "token",
		Value:     "synthetic",
		SourceURL: "file://a.js",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "Type,Risk,ReviewPriority,FilterStatus") {
		t.Fatalf("grouped CSV header missing: %s", data)
	}
}

func TestWriterKeepsOccurrenceSpecificSemanticVerdicts(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat", true: "grouped"}[grouped], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings.json")
			writer, err := NewWriter(path, false, grouped)
			if err != nil {
				t.Fatal(err)
			}

			likelyFalsePositive := SecretFindingData{
				Type:           "api_key_assignment",
				Value:          "same-value",
				SourceURL:      "file://config.js",
				Line:           4,
				ByteOffset:     18,
				Context:        []string{`const example_key = "same-value"`},
				Occurrences:    1,
				ReviewPriority: "low",
				FilterStatus:   "likely_false_positive",
				FilterScore:    0.98,
			}
			uncertain := SecretFindingData{
				Type:         "api_key_assignment",
				Value:        "same-value",
				SourceURL:    "file://config.js",
				Line:         9,
				ByteOffset:   146,
				Context:      []string{`const api_key = "same-value"`},
				Occurrences:  1,
				FilterStatus: "uncertain",
				FilterScore:  0.51,
			}
			for _, item := range []SecretFindingData{likelyFalsePositive, uncertain, uncertain} {
				if err := writer.WriteFinding("file://config.js", item); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var findings []SecretFindingData
			if grouped {
				var bySource map[string][]SecretFindingData
				if err := json.Unmarshal(data, &bySource); err != nil {
					t.Fatal(err)
				}
				findings = bySource["file://config.js"]
			} else if err := json.Unmarshal(data, &findings); err != nil {
				t.Fatal(err)
			}

			if len(findings) != 2 {
				t.Fatalf("stored %d findings, expected two occurrence-specific records: %+v", len(findings), findings)
			}
			byStatus := make(map[string]SecretFindingData, len(findings))
			for _, item := range findings {
				byStatus[item.FilterStatus] = item
			}
			if item := byStatus["likely_false_positive"]; item.ByteOffset != 18 || item.Line != 4 || item.ReviewPriority != "low" || item.Occurrences != 1 {
				t.Fatalf("likely-false-positive occurrence was lost or changed: %+v", item)
			}
			if item := byStatus["uncertain"]; item.ByteOffset != 146 || item.Line != 9 || item.Occurrences != 2 {
				t.Fatalf("identical uncertain occurrence was not deduplicated: %+v", item)
			}
		})
	}
}

func TestWriterRawModesKeepDistinctOccurrencesAndDeduplicateExactRepeats(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat", true: "grouped"}[grouped], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings.json")
			writer, err := NewWriter(path, true, grouped)
			if err != nil {
				t.Fatal(err)
			}

			first := SecretFindingData{Type: "token", Value: "same-value", SourceURL: "file://config.js", Line: 1, ByteOffset: 4, FilterStatus: "likely_false_positive"}
			second := SecretFindingData{Type: "token", Value: "same-value", SourceURL: "file://config.js", Line: 2, ByteOffset: 40, FilterStatus: "uncertain"}
			for _, item := range []SecretFindingData{first, second, second} {
				if err := writer.WriteFinding("file://config.js", item); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var values []string
			if grouped {
				var bySource map[string][]string
				if err := json.Unmarshal(data, &bySource); err != nil {
					t.Fatal(err)
				}
				values = bySource["file://config.js"]
			} else if err := json.Unmarshal(data, &values); err != nil {
				t.Fatal(err)
			}
			if len(values) != 2 || values[0] != "same-value" || values[1] != "same-value" {
				t.Fatalf("raw output did not preserve distinct occurrences while deduplicating the exact repeat: %v", values)
			}
		})
	}
}

func TestFindingKeyIncludesOccurrenceAndFilterStatus(t *testing.T) {
	base := SecretFindingData{Type: "token", Value: "same-value", SourceURL: "file://config.js", Line: 1, ByteOffset: 8, FilterStatus: "uncertain"}
	for name, mutate := range map[string]func(*SecretFindingData){
		"line":          func(item *SecretFindingData) { item.Line++ },
		"byte offset":   func(item *SecretFindingData) { item.ByteOffset++ },
		"filter status": func(item *SecretFindingData) { item.FilterStatus = "likely_false_positive" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if findingKey(base) == findingKey(changed) {
				t.Fatalf("finding key ignored %s", name)
			}
		})
	}
}
