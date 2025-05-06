package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Writer struct {
	file               *os.File
	mu                 sync.Mutex
	format             string
	rawMode            bool
	isFirstRawJsonWrite bool
	count              int
}

/*
   Creates a new writer instance for outputting secrets to a file
   Accepts rawMode flag.
*/
func NewWriter(outputPath string, rawMode bool) (*Writer, error) {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	ext := strings.ToLower(filepath.Ext(outputPath))
	format := "txt"
	if ext == ".json" {
		format = "json"
	} else if ext == ".csv" {
		format = "csv"
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}

	writer := &Writer{
		file:               file,
		format:             format,
		rawMode:            rawMode,
		isFirstRawJsonWrite: true,
		count:              0,
	}

	if format == "json" && !rawMode {
		_, err = file.WriteString("[\n")
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write JSON header: %v", err)
		}
	} else if format == "csv" && !rawMode {
		_, err = file.WriteString("Type,Value,URL,Context\n")
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
	var err error

	if w.rawMode {
		if w.format == "json" {
			prefix := ""
			if w.isFirstRawJsonWrite {
				prefix = "["
				w.isFirstRawJsonWrite = false
			} else {
				prefix = ","
			}
			jsonValueBytes, jsonErr := json.Marshal(value)
			if jsonErr != nil {
				return fmt.Errorf("failed to marshal raw JSON value: %v", jsonErr)
			}
			output = prefix + string(jsonValueBytes)
		} else {
			output = value + "\n"
		}
		_, err = w.file.WriteString(output)

	} else {
		if w.format == "json" {
			secret := map[string]interface{}{
				"type":    secretType,
				"value":   value,
				"url":     url,
				"context": context,
			}
			jsonBytes, jsonErr := json.MarshalIndent(secret, "  ", "  ")
			if jsonErr != nil {
				return fmt.Errorf("failed to marshal standard JSON: %v", jsonErr)
			}
			if w.count > 1 {
				output = ",\n  " + string(jsonBytes)
			} else {
				output = "  " + string(jsonBytes)
			}
			_, err = w.file.WriteString(output)

		} else if w.format == "csv" {
			output = fmt.Sprintf("%s,\"%s\",\"%s\",\"%s\"\n",
				secretType, escapeCsv(value), escapeCsv(url), escapeCsv(context))
			_, err = w.file.WriteString(output)

		} else {
			output = fmt.Sprintf("[%s] %s\nURL: %s\nContext: %s\n\n",
				secretType, value, url, context)
			_, err = w.file.WriteString(output)
		}
	}

	return err
}

/*
   Finalizes and closes the output file, properly terminating
   JSON formats if needed.
*/
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	var finalWriteErr error
	if w.format == "json" {
		if w.rawMode {
			if !w.isFirstRawJsonWrite {
				_, finalWriteErr = w.file.WriteString("]")
			} else {
				_, finalWriteErr = w.file.WriteString("[]")
			}
		} else {
			_, finalWriteErr = w.file.WriteString("\n]")
		}
	}

	closeErr := w.file.Close()
	w.file = nil

	if finalWriteErr != nil {
		return fmt.Errorf("failed to finalize output file: %v", finalWriteErr)
	}
	return closeErr
}

func escapeCsv(field string) string {
	return strings.ReplaceAll(field, "\"", "\"\"")
}

func (w *Writer) GetCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
