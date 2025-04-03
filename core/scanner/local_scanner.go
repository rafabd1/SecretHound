package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rafabd1/SecretHound/core/detector"
	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

// LocalScannerConfig holds the configuration for local scanner
type LocalScannerConfig struct {
	// Number of concurrent goroutines
	Concurrency int
	
	// Be less strict with validation for files in test/example directories
	AllowTestExamples bool
	
	// Maximum file size to process (in bytes)
	MaxFileSize int64
	
	// Process binary files
	ProcessBinaryFiles bool
}

// LocalScanner scans local files for secrets
type LocalScanner struct {
	detector    *detector.Detector
	writer      *output.Writer
	logger      *output.Logger
	config      LocalScannerConfig
	stats       LocalScanStats
	mu          sync.Mutex
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// LocalScanStats holds statistics for local scanning
type LocalScanStats struct {
	TotalFiles     int
	ProcessedFiles int
	SkippedFiles   int
	FailedFiles    int
	TotalSecrets   int
	TotalBytes     int64
	StartTime      time.Time
	EndTime        time.Time
}

// NewLocalScanner creates a new local scanner
func NewLocalScanner(
	patternManager *patterns.PatternManager,
	writer *output.Writer,
	logger *output.Logger,
	config LocalScannerConfig,
) *LocalScanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Default values if not set
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = 10 * 1024 * 1024 // 10MB
	}
	
	// Create detector with local file mode enabled
	secretDetector := detector.NewDetector(
		patternManager,
		logger,
		detector.Config{
			LocalFileMode: true,
			AllowTestExamples: config.AllowTestExamples,
			ContextSize: 100,
			MinConfidence: 0.5,
		},
	)
	
	return &LocalScanner{
		detector:   secretDetector,
		writer:     writer,
		logger:     logger,
		config:     config,
		ctx:        ctx,
		cancelFunc: cancel,
		stats: LocalScanStats{
			StartTime: time.Now(),
		},
	}
}

// ScanFiles scans a list of files for secrets
func (s *LocalScanner) ScanFiles(files []string) error {
	s.mu.Lock()
	s.stats = LocalScanStats{
		TotalFiles: len(files),
		StartTime:  time.Now(),
	}
	s.mu.Unlock()
	
	// Get unique, sorted files for deterministic processing
	uniqueFiles := s.getUniqueAndSortedFiles(files)
	
	s.logger.Info("Found %d local files to scan", len(uniqueFiles))
	
	// Create a progress bar
	progressBar := output.NewProgressBar(len(uniqueFiles), 40)
	progressBar.SetPrefix("Processing: ")
	
	// Connect progress bar to logger
	s.logger.SetProgressBar(progressBar)
	
	// Start the progress bar
	progressBar.Start()
	progressBar.Update(0)
	progressBar.SetSuffix("Secrets: 0 | Rate: 0.0/s")
	
	// Small delay to ensure the bar is rendered
	time.Sleep(50 * time.Millisecond)
	
	// Set up progress tracking
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	done := make(chan struct{})
	tickerRunning := true
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Recovered from panic in progress update: %v", r)
			}
		}()
		
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
	
	// Process files concurrently
	var wg sync.WaitGroup
	resultChan := make(chan int, len(uniqueFiles))
	errorChan := make(chan error, len(uniqueFiles))
	
	// Semaphore to limit concurrency
	sem := make(chan struct{}, s.config.Concurrency)
	
	// Process each file
	for _, file := range uniqueFiles {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			
			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()
			
			// Process the file
			secretCount, err := s.processFile(filePath)
			
			// Update processed count
			s.mu.Lock()
			s.stats.ProcessedFiles++
			s.mu.Unlock()
			
			// Send result
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- secretCount
			}
		}(file)
	}
	
	// Wait for all processing to complete
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
		
		// Stop the ticker
		s.mu.Lock()
		if tickerRunning {
			tickerRunning = false
			close(done)
		}
		s.mu.Unlock()
	}()
	
	// Process results
	var errorList []error
	secretsFound := 0
	filesProcessed := 0
	
	for filesProcessed < len(uniqueFiles) {
		select {
		case count, ok := <-resultChan:
			if !ok {
				continue
			}
			secretsFound += count
			filesProcessed++
			
		case err, ok := <-errorChan:
			if !ok {
				continue
			}
			errorList = append(errorList, err)
			filesProcessed++
		}
	}
	
	// Ensure ticker is stopped
	s.mu.Lock()
	if tickerRunning {
		tickerRunning = false
		close(done)
	}
	s.mu.Unlock()
	
	// Stop progress bar
	progressBar.Stop()
	progressBar.Finalize()
	
	// Remove progress bar from logger
	s.logger.SetProgressBar(nil)
	
	// Flush logs
	s.logger.Flush()
	time.Sleep(50 * time.Millisecond)
	
	// Log final stats
	s.logFinalStats()
	
	// Return first error if any
	if len(errorList) > 0 {
		return fmt.Errorf("encountered %d errors during scanning, first error: %v",
			len(errorList), errorList[0])
	}
	
	return nil
}

// processFile processes a single file
func (s *LocalScanner) processFile(filePath string) (int, error) {
	// Check if context is canceled
	select {
	case <-s.ctx.Done():
		return 0, fmt.Errorf("processing interrupted")
	default:
		// Continue processing
	}
	
	// Check if file exists and is readable
	fi, err := os.Stat(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("cannot access file %s: %v", filePath, err)
	}
	
	// Skip directories
	if fi.IsDir() {
		s.incrementSkippedFiles()
		return 0, nil
	}
	
	// Check file size
	if fi.Size() > s.config.MaxFileSize {
		s.incrementSkippedFiles()
		s.logger.Debug("Skipping large file: %s (size: %d bytes)", filePath, fi.Size())
		return 0, nil
	}
	
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	
	// Skip binary files unless configured otherwise
	if !s.config.ProcessBinaryFiles && utils.IsBinaryContent(content) {
		s.incrementSkippedFiles()
		s.logger.Debug("Skipping binary content in file: %s", filePath)
		return 0, nil
	}
	
	// Log processing
	s.logger.Debug("Processing file: %s (size: %d bytes)", filePath, len(content))
	
	// Convert to URL format
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	fileURL := "file://" + filepath.ToSlash(absPath)
	
	// Detect secrets
	secrets, err := s.detector.DetectSecrets(string(content), fileURL)
	if err != nil {
		s.incrementFailedFiles()
		s.logger.Error("Failed to process file %s: %v", filePath, err)
		return 0, err
	}
	
	// Enhance secrets with line numbers
	for i := range secrets {
		if secrets[i].Line == 0 {
			secrets[i].Line = utils.FindLineNumber(string(content), secrets[i].Value)
		}
	}
	
	// Log and write detected secrets
	for _, secret := range secrets {
		// Add line number to URL
		locationURL := fmt.Sprintf("%s#L%d", fileURL, secret.Line)
		
		// Log the secret
		s.logger.SecretFound(secret.Type, secret.Value, locationURL)
		
		// Write to output file if configured
		if s.writer != nil {
			err := s.writer.WriteSecret(secret.Type, secret.Value, locationURL, secret.Context, secret.Line)
			if err != nil {
				s.logger.Error("Failed to write secret to output: %v", err)
			}
		}
	}
	
	// Log summary
	if len(secrets) > 0 {
		s.logger.Success("Found %d secrets in %s", len(secrets), filePath)
	} else {
		s.logger.Debug("No secrets found in %s", filePath)
	}
	
	// Update stats
	s.mu.Lock()
	s.stats.TotalSecrets += len(secrets)
	s.stats.TotalBytes += fi.Size()
	s.mu.Unlock()
	
	return len(secrets), nil
}

// getUniqueAndSortedFiles removes duplicates and sorts files
func (s *LocalScanner) getUniqueAndSortedFiles(files []string) []string {
	// Remove duplicates
	uniqueMap := make(map[string]bool)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err == nil {
			uniqueMap[absPath] = true
		} else {
			uniqueMap[file] = true
		}
	}
	
	// Convert to slice
	uniqueFiles := make([]string, 0, len(uniqueMap))
	for file := range uniqueMap {
		uniqueFiles = append(uniqueFiles, file)
	}
	
	// Sort for deterministic processing
	sort.Strings(uniqueFiles)
	
	return uniqueFiles
}

// incrementFailedFiles increments the failed files counter
func (s *LocalScanner) incrementFailedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.FailedFiles++
}

// incrementSkippedFiles increments the skipped files counter
func (s *LocalScanner) incrementSkippedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.SkippedFiles++
}

// logFinalStats logs final statistics
func (s *LocalScanner) logFinalStats() {
	// Record end time
	s.mu.Lock()
	s.stats.EndTime = time.Now()
	duration := s.stats.EndTime.Sub(s.stats.StartTime)
	filesPerSecond := float64(s.stats.ProcessedFiles) / duration.Seconds()
	totalProcessed := s.stats.ProcessedFiles
	skippedFiles := s.stats.SkippedFiles
	failedFiles := s.stats.FailedFiles
	s.mu.Unlock()
	
	timeColor := color.New(color.FgHiBlack).SprintfFunc()
	timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))
	
	// Small delay for logs to flush
	time.Sleep(100 * time.Millisecond)
	
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Local file processing completed in %.2f seconds", duration.Seconds()))
	
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Processed %d files (%.2f files/second)", totalProcessed, filesPerSecond))
	
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		timeStr,
		color.CyanString("[INFO]"),
		fmt.Sprintf("Skipped %d files, failed to process %d files", skippedFiles, failedFiles))
	
	// Small delay
	time.Sleep(100 * time.Millisecond)
}

// GetStats returns scanner statistics
func (s *LocalScanner) GetStats() LocalScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	return s.stats
}

// Cleanup releases resources
func (s *LocalScanner) Cleanup() {
	s.cancelFunc()
}
