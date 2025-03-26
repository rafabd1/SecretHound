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
		_, err = file.WriteString("Type,Value,URL,Context,Timestamp\n")
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

	// Create output object based on format
	var output string
	if w.jsonMode {
		// Create JSON object
		secret := map[string]interface{}{
			"type":      secretType,
			"value":     value,
			"url":       url,
			"context":   context,
			// Remove line field
			"timestamp": time.Now().Format(time.RFC3339),
		}

		// Marshal to JSON
		jsonBytes, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}

		output = string(jsonBytes)
	} else {
		// Create text output
		output = fmt.Sprintf("[%s] %s\nURL: %s\nContext: %s\nTimestamp: %s\n\n",
			secretType, value, url, context, time.Now().Format(time.RFC3339))
	}
	// Write to file
	_, err := fmt.Fprintln(w.file, output)
	return err
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
