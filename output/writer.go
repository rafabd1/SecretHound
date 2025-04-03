package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Writer struct {
	file     *os.File
	mu       sync.Mutex
	jsonMode bool
	csvMode  bool
	count    int
}

type SecretOutput struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	URL       string    `json:"url"`
	Context   string    `json:"context"`
	Timestamp time.Time `json:"timestamp"`
}

/* 
   Creates a new writer instance for outputting secrets to a file
   with format determined by the file extension
*/
func NewWriter(outputPath string) (*Writer, error) {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	ext := filepath.Ext(outputPath)
	jsonMode := ext == ".json"
	csvMode := ext == ".csv"

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

	if writer.jsonMode {
		_, err = file.WriteString("[\n")
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write JSON header: %v", err)
		}
	} else if writer.csvMode {
		_, err = file.WriteString("Type,Value,URL,Context,Timestamp\n")
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write CSV header: %v", err)
		}
	}

	return writer, nil
}

func (w *Writer) WriteSecret(secretType, value, url, context string, line int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.count++

	var output string
	if w.jsonMode {
		secret := map[string]interface{}{
			"type":      secretType,
			"value":     value,
			"url":       url,
			"context":   context,
			"timestamp": time.Now().Format(time.RFC3339),
		}

		jsonBytes, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}

		if w.count > 1 {
			output = ",\n" + string(jsonBytes)
		} else {
			output = string(jsonBytes)
		}
	} else {
		output = fmt.Sprintf("[%s] %s\nURL: %s\nContext: %s\nTimestamp: %s\n\n",
			secretType, value, url, context, time.Now().Format(time.RFC3339))
	}
	
	_, err := fmt.Fprintln(w.file, output)
	return err
}

/* 
   Finalizes and closes the output file, properly terminating 
   JSON format if needed
*/
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	if w.jsonMode {
		_, err := w.file.WriteString("\n]")
		if err != nil {
			return fmt.Errorf("failed to finalize JSON file: %v", err)
		}
	}

	err := w.file.Close()
	w.file = nil
	return err
}

func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
