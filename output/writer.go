package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Writer handles writing secrets to output file
type Writer struct {
	file     *os.File
	mu       sync.Mutex
	jsonMode bool
	csvMode  bool
	count    int
}

// SecretOutput represents a secret to be written to the output file
type SecretOutput struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	URL       string    `json:"url"`
	Line      int       `json:"line"`
	Context   string    `json:"context"`
	Timestamp time.Time `json:"timestamp"`
}

// NewWriter creates a new writer
func NewWriter(outputPath string) (*Writer, error) {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Determine output format based on extension
	ext := filepath.Ext(outputPath)
	jsonMode := ext == ".json"
	csvMode := ext == ".csv"

	// Open the file for writing
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}

	writer := &Writer{
		file:     file,
		jsonMode: jsonMode,
		csvMode:  csvMode,
		count:    0,
	}

	// Write header based on format
	if writer.jsonMode {
		// Start JSON array
		_, err = file.WriteString("[\n")
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write JSON header: %v", err)
		}
	} else if writer.csvMode {
		// Write CSV header
		_, err = file.WriteString("Type,Value,URL,Line,Context,Timestamp\n")
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write CSV header: %v", err)
		}
	}

	return writer, nil
}

// WriteSecret writes a secret to the output file
func (w *Writer) WriteSecret(secretType, value, url, context string, line int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	secret := SecretOutput{
		Type:      secretType,
		Value:     value,
		URL:       url,
		Line:      line,
		Context:   context,
		Timestamp: time.Now(),
	}

	if w.jsonMode {
		// Marshal the secret to JSON
		data, err := json.MarshalIndent(secret, "  ", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal secret to JSON: %v", err)
		}

		// Write comma if not the first entry
		if w.count > 0 {
			_, err = w.file.WriteString(",\n")
			if err != nil {
				return fmt.Errorf("failed to write JSON separator: %v", err)
			}
		}

		// Write the JSON object
		_, err = w.file.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write secret to JSON file: %v", err)
		}
	} else if w.csvMode {
		// Format the secret as CSV
		_, err := fmt.Fprintf(w.file, "%s,%s,%s,%d,%s,%s\n",
			escapeCSV(secretType),
			escapeCSV(value),
			escapeCSV(url),
			line,
			escapeCSV(context),
			secret.Timestamp.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("failed to write secret to CSV file: %v", err)
		}
	} else {
		// Plain text format
		_, err := fmt.Fprintf(w.file, "[%s] %s\nURL: %s\nLine: %d\nContext: %s\nTimestamp: %s\n\n",
			secretType,
			value,
			url,
			line,
			context,
			secret.Timestamp.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("failed to write secret to text file: %v", err)
		}
	}

	// Increment the count of secrets written
	w.count++

	// Ensure the data is written to disk
	return w.file.Sync()
}

// Close closes the writer
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	// Finalize the file format if needed
	if w.jsonMode {
		// Close the JSON array
		_, err := w.file.WriteString("\n]")
		if err != nil {
			return fmt.Errorf("failed to finalize JSON file: %v", err)
		}
	}

	// Close the file
	err := w.file.Close()
	w.file = nil
	return err
}

// GetCount returns the number of secrets written
func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

// escapeCSV escapes a string for CSV format
func escapeCSV(s string) string {
	if needsQuoting(s) {
		return fmt.Sprintf("\"%s\"", escapeQuotes(s))
	}
	return s
}

// needsQuoting checks if a string needs to be quoted in CSV
func needsQuoting(s string) bool {
	return len(s) == 0 || contains(s, '"') || contains(s, ',') || contains(s, '\n') || contains(s, '\r')
}

// escapeQuotes replaces double quotes with double double quotes
func escapeQuotes(s string) string {
	var result string
	for _, c := range s {
		if c == '"' {
			result += "\"\""
		} else {
			result += string(c)
		}
	}
	return result
}

// contains checks if a string contains a rune
func contains(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
