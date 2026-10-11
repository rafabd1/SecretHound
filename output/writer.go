package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type SecretFindingData struct {
	Type           string   `json:"type"`
	Risk           string   `json:"risk,omitempty"`
	Value          string   `json:"value"`
	SourceURL      string   `json:"source_url"`
	Line           int      `json:"line,omitempty"`
	ByteOffset     int      `json:"byte_offset"`
	Context        []string `json:"context,omitempty"`
	Occurrences    int      `json:"occurrences,omitempty"`
	Description    string   `json:"description,omitempty"`
	Confidence     float64  `json:"confidence,omitempty"`
	ReviewPriority string   `json:"review_priority,omitempty"`
	FilterStatus   string   `json:"filter_status,omitempty"`
	FilterScore    float64  `json:"filter_score,omitempty"`
}

type Writer struct {
	file              *os.File
	mu                sync.Mutex
	format            string
	rawMode           bool
	isGroupedBySource bool
	count             int

	findings     []SecretFindingData
	findingIndex map[string]int

	groupedFindings map[string][]SecretFindingData
	groupedIndex    map[string]map[string]int
}

func NewWriter(outputPath string, rawMode bool, groupedMode bool) (*Writer, error) {
	dir := filepath.Dir(outputPath)
	if outputPath != "" && dir != "." && dir != outputPath {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	ext := strings.ToLower(filepath.Ext(outputPath))
	format := "txt"
	if ext == ".json" {
		format = "json"
	} else if ext == ".csv" {
		format = "csv"
	}

	var f *os.File
	var err error
	if outputPath != "" {
		f, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
	} else {
		f = os.Stdout
	}

	w := &Writer{
		file:              f,
		format:            format,
		rawMode:           rawMode,
		isGroupedBySource: groupedMode,
		findingIndex:      make(map[string]int),
	}

	if groupedMode {
		w.groupedFindings = make(map[string][]SecretFindingData)
		w.groupedIndex = make(map[string]map[string]int)
	}

	return w, nil
}

func (w *Writer) WriteSecret(sourceForGrouping, secretType, risk, value, specificSourceURL, context, description string, line int) error {
	return w.WriteFinding(sourceForGrouping, SecretFindingData{
		Type:        secretType,
		Risk:        risk,
		Value:       value,
		SourceURL:   specificSourceURL,
		Line:        line,
		Context:     contextSlice(context),
		Occurrences: 1,
		Description: description,
	})
}

func (w *Writer) WriteFinding(sourceForGrouping string, finding SecretFindingData) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.count++
	if finding.Occurrences <= 0 {
		finding.Occurrences = 1
	}

	if w.rawMode {
		if w.isGroupedBySource {
			if _, ok := w.groupedFindings[sourceForGrouping]; !ok {
				w.groupedFindings[sourceForGrouping] = []SecretFindingData{}
				w.groupedIndex[sourceForGrouping] = map[string]int{}
			}
			key := findingKey(finding)
			if idx, ok := w.groupedIndex[sourceForGrouping][key]; ok {
				w.groupedFindings[sourceForGrouping][idx].Occurrences += finding.Occurrences
				return nil
			}
			finding.Context = nil
			finding.Description = ""
			w.groupedFindings[sourceForGrouping] = append(w.groupedFindings[sourceForGrouping], finding)
			w.groupedIndex[sourceForGrouping][key] = len(w.groupedFindings[sourceForGrouping]) - 1
			return nil
		}

		key := findingKey(finding)
		if idx, ok := w.findingIndex[key]; ok {
			w.findings[idx].Occurrences += finding.Occurrences
			return nil
		}
		finding.Context = nil
		finding.Description = ""
		w.findings = append(w.findings, finding)
		w.findingIndex[key] = len(w.findings) - 1
		return nil
	}

	if w.isGroupedBySource {
		if _, ok := w.groupedFindings[sourceForGrouping]; !ok {
			w.groupedFindings[sourceForGrouping] = []SecretFindingData{}
			w.groupedIndex[sourceForGrouping] = map[string]int{}
		}

		key := findingKey(finding)
		if idx, ok := w.groupedIndex[sourceForGrouping][key]; ok {
			mergeFinding(&w.groupedFindings[sourceForGrouping][idx], finding)
			return nil
		}

		w.groupedFindings[sourceForGrouping] = append(w.groupedFindings[sourceForGrouping], finding)
		w.groupedIndex[sourceForGrouping][key] = len(w.groupedFindings[sourceForGrouping]) - 1
		return nil
	}

	key := findingKey(finding)
	if idx, ok := w.findingIndex[key]; ok {
		mergeFinding(&w.findings[idx], finding)
		return nil
	}

	w.findings = append(w.findings, finding)
	w.findingIndex[key] = len(w.findings) - 1
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var out []byte
	var err error

	switch {
	case w.rawMode && w.isGroupedBySource:
		raw := make(map[string][]string, len(w.groupedFindings))
		for source, findings := range w.groupedFindings {
			values := make([]string, 0, len(findings))
			for _, f := range findings {
				values = append(values, f.Value)
			}
			raw[source] = values
		}
		out, err = w.marshalByFormat(raw)
	case w.rawMode && !w.isGroupedBySource:
		values := make([]string, 0, len(w.findings))
		for _, f := range w.findings {
			values = append(values, f.Value)
		}
		out, err = w.marshalByFormat(values)
	case !w.rawMode && w.isGroupedBySource:
		out, err = w.marshalByFormat(w.groupedFindings)
	default:
		out, err = w.marshalByFormat(w.findings)
	}

	if err != nil {
		if w.file != nil && w.file != os.Stdout {
			_ = w.file.Close()
			w.file = nil
		}
		return err
	}

	if w.file == os.Stdout {
		fmt.Print(string(out))
		if len(out) == 0 || out[len(out)-1] != '\n' {
			fmt.Print("\n")
		}
		return nil
	}

	if _, err := w.file.Write(out); err != nil {
		_ = w.file.Close()
		w.file = nil
		return err
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		_, _ = w.file.WriteString("\n")
	}
	err = w.file.Close()
	w.file = nil
	return err
}

func (w *Writer) marshalByFormat(v interface{}) ([]byte, error) {
	switch w.format {
	case "json":
		return json.MarshalIndent(v, "", "  ")
	case "csv":
		return marshalCSV(v)
	default:
		return marshalTXT(v)
	}
}

func marshalCSV(v interface{}) ([]byte, error) {
	var sb strings.Builder

	switch data := v.(type) {
	case []SecretFindingData:
		sb.WriteString("Type,Risk,ReviewPriority,FilterStatus,FilterScore,Confidence,Value,SourceURL,Line,ByteOffset,Occurrences,Context,Description\n")
		for _, f := range data {
			sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%.6f,%.6f,\"%s\",\"%s\",%d,%d,%d,\"%s\",\"%s\"\n",
				f.Type,
				escapeCsv(f.Risk),
				escapeCsv(f.ReviewPriority),
				escapeCsv(f.FilterStatus),
				f.FilterScore,
				f.Confidence,
				escapeCsv(f.Value),
				escapeCsv(f.SourceURL),
				f.Line,
				f.ByteOffset,
				f.Occurrences,
				escapeCsv(strings.Join(f.Context, " | ")),
				escapeCsv(f.Description),
			))
		}
	case map[string][]SecretFindingData:
		sb.WriteString("Type,Risk,ReviewPriority,FilterStatus,FilterScore,Confidence,Value,SourceURL,Line,ByteOffset,Occurrences,Context,Description\n")
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, source := range keys {
			for _, f := range data[source] {
				sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%.6f,%.6f,\"%s\",\"%s\",%d,%d,%d,\"%s\",\"%s\"\n",
					f.Type,
					escapeCsv(f.Risk),
					escapeCsv(f.ReviewPriority),
					escapeCsv(f.FilterStatus),
					f.FilterScore,
					f.Confidence,
					escapeCsv(f.Value),
					escapeCsv(source),
					f.Line,
					f.ByteOffset,
					f.Occurrences,
					escapeCsv(strings.Join(f.Context, " | ")),
					escapeCsv(f.Description),
				))
			}
		}
	case []string:
		sb.WriteString("Value\n")
		for _, value := range data {
			sb.WriteString(fmt.Sprintf("\"%s\"\n", escapeCsv(value)))
		}
	case map[string][]string:
		sb.WriteString("Source,Value\n")
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, source := range keys {
			for _, value := range data[source] {
				sb.WriteString(fmt.Sprintf("\"%s\",\"%s\"\n",
					escapeCsv(source),
					escapeCsv(value),
				))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported CSV output type")
	}

	return []byte(sb.String()), nil
}

func marshalTXT(v interface{}) ([]byte, error) {
	var sb strings.Builder

	switch data := v.(type) {
	case []SecretFindingData:
		for _, f := range data {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", f.Type, f.Value))
			if f.Risk != "" {
				sb.WriteString(fmt.Sprintf("Risk: %s\n", f.Risk))
			}
			writeTXTFilterMetadata(&sb, "", f)
			sb.WriteString(fmt.Sprintf("URL: %s\n", f.SourceURL))
			if f.Line > 0 {
				sb.WriteString(fmt.Sprintf("Line: %d\n", f.Line))
			}
			sb.WriteString(fmt.Sprintf("Byte offset: %d\n", f.ByteOffset))
			if f.Occurrences > 1 {
				sb.WriteString(fmt.Sprintf("Occurrences: %d\n", f.Occurrences))
			}
			if len(f.Context) > 0 {
				sb.WriteString(fmt.Sprintf("Context: %s\n", strings.Join(f.Context, " | ")))
			}
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("Description: %s\n", f.Description))
			}
			sb.WriteString("\n")
		}
	case map[string][]SecretFindingData:
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, source := range keys {
			sb.WriteString(source + ":\n")
			for _, f := range data[source] {
				sb.WriteString(fmt.Sprintf("\t[%s] %s\n", f.Type, f.Value))
				if f.Risk != "" {
					sb.WriteString(fmt.Sprintf("\tRisk: %s\n", f.Risk))
				}
				writeTXTFilterMetadata(&sb, "\t", f)
				if f.Line > 0 {
					sb.WriteString(fmt.Sprintf("\tLine: %d\n", f.Line))
				}
				sb.WriteString(fmt.Sprintf("\tByte offset: %d\n", f.ByteOffset))
				if f.Occurrences > 1 {
					sb.WriteString(fmt.Sprintf("\tOccurrences: %d\n", f.Occurrences))
				}
				if len(f.Context) > 0 {
					sb.WriteString(fmt.Sprintf("\tContext: %s\n", strings.Join(f.Context, " | ")))
				}
				if f.Description != "" {
					sb.WriteString(fmt.Sprintf("\tDescription: %s\n", f.Description))
				}
				sb.WriteString("\n")
			}
		}
	case []string:
		for _, value := range data {
			sb.WriteString(value + "\n")
		}
	case map[string][]string:
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, source := range keys {
			sb.WriteString(source + ":\n")
			for _, value := range data[source] {
				sb.WriteString("\t" + value + "\n")
			}
			sb.WriteString("\n")
		}
	default:
		return nil, fmt.Errorf("unsupported TXT output type")
	}

	return []byte(sb.String()), nil
}

func contextSlice(context string) []string {
	if strings.TrimSpace(context) == "" {
		return []string{}
	}
	return []string{context}
}

func appendUniqueString(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func findingKey(finding SecretFindingData) string {
	return finding.Type + "\x00" + finding.Value + "\x00" + finding.SourceURL + "\x00" +
		strconv.Itoa(finding.Line) + "\x00" + strconv.Itoa(finding.ByteOffset) + "\x00" + finding.FilterStatus
}

func mergeFinding(existing *SecretFindingData, incoming SecretFindingData) {
	for _, context := range incoming.Context {
		existing.Context = appendUniqueString(existing.Context, context)
	}
	existing.Occurrences += incoming.Occurrences
	if existing.Line == 0 || (incoming.Line > 0 && incoming.Line < existing.Line) {
		existing.Line = incoming.Line
	}
	if incoming.Confidence > existing.Confidence {
		existing.Confidence = incoming.Confidence
	}
	if filterStatusRank(incoming.FilterStatus) > filterStatusRank(existing.FilterStatus) {
		existing.FilterStatus = incoming.FilterStatus
		existing.FilterScore = incoming.FilterScore
	}
	if existing.FilterStatus == "likely_false_positive" {
		existing.ReviewPriority = "low"
	} else {
		existing.ReviewPriority = incoming.ReviewPriority
		if existing.ReviewPriority == "low" {
			existing.ReviewPriority = ""
		}
	}
}

func filterStatusRank(status string) int {
	switch status {
	case "not_likely_false_positive":
		return 4
	case "classification_error":
		return 3
	case "uncertain":
		return 2
	case "likely_false_positive":
		return 1
	default:
		return 0
	}
}

func writeTXTFilterMetadata(sb *strings.Builder, prefix string, finding SecretFindingData) {
	if finding.ReviewPriority != "" {
		sb.WriteString(fmt.Sprintf("%sReview priority: %s\n", prefix, finding.ReviewPriority))
	}
	if finding.FilterStatus != "" {
		sb.WriteString(fmt.Sprintf("%sFilter status: %s\n", prefix, finding.FilterStatus))
		sb.WriteString(fmt.Sprintf("%sFilter score: %.6f\n", prefix, finding.FilterScore))
	}
}

func escapeCsv(field string) string {
	return strings.ReplaceAll(field, "\"", "\"\"")
}

func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
