package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestLocalScannerHonorsParentCancellation(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(filePath, []byte("password=not-processed"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := output.NewLogger(false, true)
	t.Cleanup(logger.Close)
	localScanner := NewLocalScannerWithContext(ctx, patterns.NewPatternManager(), nil, logger, LocalScannerConfig{
		Concurrency: 1,
		NoProgress:  true,
		Silent:      true,
	})
	t.Cleanup(localScanner.Cleanup)

	stats, err := localScanner.ScanFiles([]string{filePath})
	if err != nil {
		t.Fatalf("ScanFiles() error = %v, want controlled completion", err)
	}
	if stats.ProcessedFiles != 0 || stats.TotalSecrets != 0 {
		t.Fatalf("unexpected stats after cancellation: %+v", stats)
	}
}
