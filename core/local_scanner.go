package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/secrethound/output"
	"github.com/secrethound/utils"
)

// LocalScanner handles scanning of local files
type LocalScanner struct {
	processor   *Processor
	writer      *output.Writer
	logger      *output.Logger
	concurrency int
	stats       LocalScannerStats
	mu          sync.Mutex
}

// LocalScannerStats tracks statistics for the local scanner
type LocalScannerStats struct {
	TotalFiles     int
	ProcessedFiles int
	FailedFiles    int
	TotalSecrets   int
	TotalBytes     int64
	StartTime      time.Time
	EndTime        time.Time
}

// NewLocalScanner creates a new local file scanner
func NewLocalScanner(processor *Processor, writer *output.Writer, logger *output.Logger) *LocalScanner {
	return &LocalScanner{
		processor:   processor,
		writer:      writer,
		logger:      logger,
		concurrency: 10, // Default concurrency
		stats: LocalScannerStats{
			StartTime: time.Now(),
		},
	}
}

// SetConcurrency sets the concurrency level for file processing
func (s *LocalScanner) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

// ScanFiles processes a list of local files
func (s *LocalScanner) ScanFiles(files []string) error {
	s.mu.Lock()
	s.stats.TotalFiles = len(files)
	s.stats.StartTime = time.Now()
	s.mu.Unlock()

	s.logger.Info("Starting to scan %d local files", len(files))

	// Create a progress bar
	progressBar := output.NewProgressBar(len(files), 40)
	progressBar.SetPrefix("Processing: ")
	progressBar.Start()

	// Create a ticker to update progress
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Start ticker goroutine to update progress bar
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				s.mu.Lock()
				processedCount := s.stats.ProcessedFiles
				secretsFound := s.stats.TotalSecrets
				s.mu.Unlock()

				// Update progress bar
				progressBar.Update(processedCount)
				progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s",
					secretsFound,
					float64(processedCount)/time.Since(s.stats.StartTime).Seconds()))
			case <-done:
				return
			}
		}
	}()

	// Process files using a worker pool
	pool := utils.NewWorkerPool(s.concurrency, len(files))
	
	// Submit each file for processing
	for _, file := range files {
		filePath := file // Create a copy for the closure
		pool.Submit(func() (interface{}, error) {
			return s.processFile(filePath)
		})
	}

	// Collect results
	secretsFound := 0
	var errorList []error
	
	// Process results as they come in
	for result := range pool.Results() {
		res := result.(int)
		secretsFound += res
	}
	
	// Process errors
	for err := range pool.Errors() {
		errorList = append(errorList, err)
	}
	
	// Wait for all files to be processed
	pool.Wait()
	
	// Signal ticker goroutine to stop
	close(done)
	
	// Stop the progress bar
	progressBar.Stop()
	
	// Record end time and log summary
	s.mu.Lock()
	s.stats.EndTime = time.Now()
	s.stats.TotalSecrets = secretsFound
	duration := s.stats.EndTime.Sub(s.stats.StartTime)
	filesPerSecond := float64(s.stats.ProcessedFiles) / duration.Seconds()
	s.mu.Unlock()
	
	// Print statistics
	s.logger.Info("Local file processing completed in %.2f seconds", duration.Seconds())
	s.logger.Info("Processed %d files (%.2f files/second)", s.stats.ProcessedFiles, filesPerSecond)
	s.logger.Info("Found %d secrets in local files", secretsFound)
	s.logger.Info("Failed to process %d files", s.stats.FailedFiles)
	
	// If there were errors, return the first one
	if len(errorList) > 0 {
		return fmt.Errorf("encountered %d errors during local file scanning, first error: %v", 
			len(errorList), errorList[0])
	}
	
	return nil
}

// processFile scans a single file for secrets
func (s *LocalScanner) processFile(filePath string) (int, error) {
	// Check if the file exists and is readable
	fi, err := os.Stat(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("cannot access file %s: %v", filePath, err)
	}
	
	// Skip directories (should be filtered earlier, but just to be safe)
	if fi.IsDir() {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("%s is a directory, not a file", filePath)
	}
	
	// Skip files that are too large (> 10MB)
	if fi.Size() > 10*1024*1024 {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("file %s is too large (> 10MB)", filePath)
	}
	
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	
	// Skip if file appears to be binary
	if utils.IsBinaryContent(content) {
		s.incrementProcessedFiles()
		s.logger.Debug("Skipping binary content in file: %s", filePath)
		return 0, nil
	}
	
	// Convert to string and process
	fileContent := string(content)
	
	// Create a custom URL for local files using absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath // Fall back to the provided path
	}
	localURL := "file://" + filepath.ToSlash(absPath)
	
	// Process the content
	secrets, err := s.processor.ProcessJSContent(fileContent, localURL)
	if err != nil {
		s.incrementFailedFiles()
		s.logger.Error("Failed to process file %s: %v", filePath, err)
		return 0, err
	}
	
	// Write secrets to output file if configured
	if s.writer != nil && len(secrets) > 0 {
		for _, secret := range secrets {
			err := s.writer.WriteSecret(secret.Type, secret.Value, localURL, secret.Context, secret.Line)
			if err != nil {
				s.logger.Error("Failed to write secret from file %s to output: %v", filePath, err)
			}
		}
	}
	
	// Log the secrets found
	if len(secrets) > 0 {
		s.logger.Success("Found %d secrets in %s", len(secrets), filePath)
	}
	
	// Update stats
	s.mu.Lock()
	s.stats.ProcessedFiles++
	s.stats.TotalSecrets += len(secrets)
	s.stats.TotalBytes += fi.Size()
	s.mu.Unlock()
	
	return len(secrets), nil
}

// incrementProcessedFiles increments the count of processed files
func (s *LocalScanner) incrementProcessedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ProcessedFiles++
}

// incrementFailedFiles increments the count of failed files
func (s *LocalScanner) incrementFailedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.FailedFiles++
	s.stats.ProcessedFiles++ // Still count as processed for total tracking
}

// GetStats returns current scanner statistics
func (s *LocalScanner) GetStats() LocalScannerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	statsCopy := s.stats
	return statsCopy
}
