package output

import (
	"io"
	"os"
	"testing"
)

func TestCoordinateOutputDoesNotClearLineWithoutProgressBar(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = originalStderr
		_ = reader.Close()
	}()

	controller := &TerminalController{isTerminal: true}
	controller.CoordinateOutput(func() {})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 0 {
		t.Fatalf("unexpected terminal control output without progress bar: %q", captured)
	}
}
