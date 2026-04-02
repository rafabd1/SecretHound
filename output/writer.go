package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type SecretFindingData struct {
	Type        string   `json:"type"`
	Risk        string   `json:"risk,omitempty"`
	Value       string   `json:"value"`
	SourceURL   string   `json:"source_url"`
	Context     []string `json:"context,omitempty"`
	Occurrences int      `json:"occurrences,omitempty"`
	Description string   `json:"description,omitempty"`
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
	w.mu.Lock()
	defer w.mu.Unlock()

	w.count++

	if w.rawMode {
		if w.isGroupedBySource {
			if _, ok := w.groupedFindings[sourceForGrouping]; !ok {
				w.groupedFindings[sourceForGrouping] = []SecretFindingData{}
				w.groupedIndex[sourceForGrouping] = map[string]int{}
			}
			key := secretType + "\x00" + value + "\x00" + specificSourceURL
			if idx, ok := w.groupedIndex[sourceForGrouping][key]; ok {
				w.groupedFindings[sourceForGrouping][idx].Occurrences++
				return nil
			}
			w.groupedFindings[sourceForGrouping] = append(w.groupedFindings[sourceForGrouping], SecretFindingData{
				Type:        secretType,
				Risk:        risk,
				Value:       value,
				SourceURL:   specificSourceURL,
				Occurrences: 1,
			})
			w.groupedIndex[sourceForGrouping][key] = len(w.groupedFindings[sourceForGrouping]) - 1
			return nil
		}

		key := secretType + "\x00" + value + "\x00" + specificSourceURL
		if idx, ok := w.findingIndex[key]; ok {
			w.findings[idx].Occurrences++
			return nil
		}
		w.findings = append(w.findings, SecretFindingData{
			Type:        secretType,
			Risk:        risk,
			Value:       value,
			SourceURL:   specificSourceURL,
			Occurrences: 1,
		})
		w.findingIndex[key] = len(w.findings) - 1
		return nil
	}

	if w.isGroupedBySource {
		if _, ok := w.groupedFindings[sourceForGrouping]; !ok {
			w.groupedFindings[sourceForGrouping] = []SecretFindingData{}
			w.groupedIndex[sourceForGrouping] = map[string]int{}
		}

		key := secretType + "\x00" + value + "\x00" + specificSourceURL
		if idx, ok := w.groupedIndex[sourceForGrouping][key]; ok {
			w.groupedFindings[sourceForGrouping][idx].Context = appendUniqueString(w.groupedFindings[sourceForGrouping][idx].Context, context)
			w.groupedFindings[sourceForGrouping][idx].Occurrences++
			return nil
		}

		w.groupedFindings[sourceForGrouping] = append(w.groupedFindings[sourceForGrouping], SecretFindingData{
			Type:        secretType,
			Risk:        risk,
			Value:       value,
			SourceURL:   specificSourceURL,
			Context:     contextSlice(context),
			Occurrences: 1,
			Description: description,
		})
		w.groupedIndex[sourceForGrouping][key] = len(w.groupedFindings[sourceForGrouping]) - 1
		return nil
	}

	key := secretType + "\x00" + value + "\x00" + specificSourceURL
	if idx, ok := w.findingIndex[key]; ok {
		w.findings[idx].Context = appendUniqueString(w.findings[idx].Context, context)
		w.findings[idx].Occurrences++
		return nil
	}

	w.findings = append(w.findings, SecretFindingData{
		Type:        secretType,
		Risk:        risk,
		Value:       value,
		SourceURL:   specificSourceURL,
		Context:     contextSlice(context),
		Occurrences: 1,
		Description: description,
	})
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
		sb.WriteString("Type,Risk,Value,SourceURL,Occurrences,Context,Description\n")
		for _, f := range data {
			sb.WriteString(fmt.Sprintf("%s,%s,\"%s\",\"%s\",%d,\"%s\",\"%s\"\n",
				f.Type,
				escapeCsv(f.Risk),
				escapeCsv(f.Value),
				escapeCsv(f.SourceURL),
				f.Occurrences,
				escapeCsv(strings.Join(f.Context, " | ")),
				escapeCsv(f.Description),
			))
		}
	case map[string][]SecretFindingData:
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, source := range keys {
			for _, f := range data[source] {
				sb.WriteString(fmt.Sprintf("%s,%s,\"%s\",\"%s\",%d,\"%s\",\"%s\"\n",
					f.Type,
					escapeCsv(f.Risk),
					escapeCsv(f.Value),
					escapeCsv(source),
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
			sb.WriteString(fmt.Sprintf("URL: %s\n", f.SourceURL))
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

func escapeCsv(field string) string {
	return strings.ReplaceAll(field, "\"", "\"\"")
}

func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
