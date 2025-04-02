package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

// LocalScanner handles scanning of local files
type LocalScanner struct {
	processor   *Processor
	writer      *output.Writer
	logger      *output.Logger
	concurrency int
	stats       LocalScannerStats
	mu          sync.Mutex
	ctx         context.Context
	cancelFunc  context.CancelFunc
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
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LocalScanner{
		processor:   processor,
		writer:      writer,
		logger:      logger,
		concurrency: 10, // Default concurrency
		stats: LocalScannerStats{
			StartTime: time.Now(),
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// SetConcurrency sets the concurrency level for file processing
func (s *LocalScanner) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

// ScanFiles processes a list of local files
func (s *LocalScanner) ScanFiles(files []string) error {
    // Get a unique ID for this execution to ensure determinism
    executionID := GetUniqueExecutionID()
    s.logger.Debug("Started scan execution #%d with %d files", executionID, len(files))
    
    // Reset components to ensure clean state
    s.processor.CompleteReset()
    s.logger.ResetState()
    
    // Initialize RegexManager with fresh patterns
    err := s.processor.InitializeRegexManager()
    if err != nil {
        return fmt.Errorf("failed to initialize RegexManager: %w", err)
    }
    s.logger.Debug("Initialized RegexManager with %d patterns", s.processor.GetRegexPatternCount())
    
    // Reset scanner stats
    s.mu.Lock()
    s.stats = LocalScannerStats{
        TotalFiles: len(files),
        StartTime: time.Now(),
    }
    s.mu.Unlock()
	
	// Remove duplicates from input files and sort for deterministic processing
	uniqueFiles := s.getUniqueAndSortedFiles(files)
	files = uniqueFiles
	
	s.mu.Lock()
	s.stats.TotalFiles = len(files)
	s.stats.StartTime = time.Now()
	s.mu.Unlock()

	s.logger.Info("Found %d local files to scan", len(files))

	// Create a progress bar
	progressBar := output.NewProgressBar(len(files), 40)
	progressBar.SetPrefix("Processing: ")
	
	// Connect progress bar to logger immediately
	s.logger.SetProgressBar(progressBar)
	
	// Start the progress bar and make it visible
	progressBar.Start()
	
	// Render an initial update to ensure it appears
	progressBar.Update(0)
	progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: 0.0/s", 0))
	
	// Force a small pause to ensure the bar is rendered before processing starts
	time.Sleep(50 * time.Millisecond)

	// Create a ticker to update progress
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Start ticker goroutine to update progress bar
	done := make(chan struct{})
	tickerDone := false
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

	// Create a custom worker pool with semaphore instead of using a more complex pool
	var wg sync.WaitGroup
	resultChan := make(chan int, len(files))
	errorChan := make(chan error, len(files))
	
	// Semaphore to limit concurrency
	sem := make(chan struct{}, s.concurrency)
	
	// Launch workers for each file
	for _, file := range files {
		filePath := file // Create a copy for closure
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }() // Release slot when done
			
			// Process the file
			count, err := s.processFile(filePath)
			
			// Update progress counter regardless of result
			s.mu.Lock()
			s.stats.ProcessedFiles++
			processedCount := s.stats.ProcessedFiles
			s.mu.Unlock()
			
			// Update progress bar for each completed file
			progressBar.Update(processedCount)
			
			// Send result or error
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- count
			}
		}()
	}
	
	// Wait for all goroutines in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
		
		// Ensure we only close done channel once
		s.mu.Lock()
		if !tickerDone {
			tickerDone = true
			close(done) // Signal ticker to stop
		}
		s.mu.Unlock()
	}()
	
	// Process results without a timeout
	secretsFound := 0
	var errorList []error
	
	// Keep reading from channels until completion
	filesProcessed := 0
	totalFiles := len(files)
	
	for filesProcessed < totalFiles {
		select {
		case res, ok := <-resultChan:
			if (!ok) {
				// Channel closed
				continue
			}
			secretsFound += res
			filesProcessed++
		case err, ok := <-errorChan:
			if (!ok) {
				// Channel closed
				continue
			}
			errorList = append(errorList, err)
			filesProcessed++
		}
	}
	
	// Make sure ticker goroutine is stopped
	s.mu.Lock()
	if !tickerDone {
		tickerDone = true
		close(done)
	}
	s.mu.Unlock()
	
	// Stop and finalize the progress bar
	progressBar.Stop()
	progressBar.Finalize()
	
	// Remove the progress bar from the logger
	s.logger.SetProgressBar(nil)
	
	// Importante: Aguardar a conclusão do processamento de todos os logs
	// antes de mostrar as estatísticas finais
	if s.logger != nil {
		s.logger.Flush()
		time.Sleep(50 * time.Millisecond) // Pequena pausa para garantir que todos os logs foram processados
	}
	
	// Agora é seguro mostrar as estatísticas finais, depois que todos os segredos foram exibidos
	s.logFinalStats()
	
	// If there were errors, return the first one
	if len(errorList) > 0 {
		return fmt.Errorf("encountered %d errors during local file scanning, first error: %v", 
			len(errorList), errorList[0])
	}
	
	return nil
}

// getUniqueAndSortedFiles removes duplicates and sorts files for deterministic processing
func (s *LocalScanner) getUniqueAndSortedFiles(files []string) []string {
	// Remove duplicates
	uniqueFilesMap := make(map[string]bool)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err == nil {
			uniqueFilesMap[absPath] = true
		} else {
			uniqueFilesMap[file] = true
		}
	}
	
	// Convert to slice
	uniqueFiles := make([]string, 0, len(uniqueFilesMap))
	for file := range uniqueFilesMap {
		uniqueFiles = append(uniqueFiles, file)
	}
	
	// Sort for deterministic processing order
	sort.Strings(uniqueFiles)
	
	return uniqueFiles
}

// processFile scans a single file for secrets
func (s *LocalScanner) processFile(filePath string) (int, error) {
	// Check if context is canceled
	select {
	case <-s.ctx.Done():
		return 0, fmt.Errorf("processing interrupted")
	default:
		// Continue processing
	}
	
	// Adicione depuração
	fmt.Printf("DEBUG: Processing file %s\n", filePath)
	
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
	
	// Adicione mais logs de depuração
	fmt.Printf("DEBUG: Processing content with length %d bytes\n", len(fileContent))
	
	// Process the content
	secrets, err := s.processor.ProcessJSContent(fileContent, localURL)
	if err != nil {
		s.incrementFailedFiles()
		s.logger.Error("Failed to process file %s: %v", filePath, err)
		return 0, err
	}
	
	// Depuração
	fmt.Printf("DEBUG: Found %d secrets in file %s\n", len(secrets), filePath)
	
	// Log the secrets found for this specific file
	for _, secret := range secrets {
		s.logger.SecretFound(secret.Type, secret.Value, localURL)
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
	
	// Log summarizing how many secrets were found in this file
	if len(secrets) > 0 {
		s.logger.Success("Found %d secrets in %s", len(secrets), filePath)
	}
	
	// Update stats
	s.mu.Lock()
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

// Cleanup cancels context and releases resources
func (s *LocalScanner) Cleanup() {
	s.cancelFunc()
}

// logFinalStats logs the final statistics in a deterministic order
func (s *LocalScanner) logFinalStats() {
    // Record end time and log summary
    s.mu.Lock()
    s.stats.EndTime = time.Now()
    duration := s.stats.EndTime.Sub(s.stats.StartTime)
    filesPerSecond := float64(s.stats.ProcessedFiles) / duration.Seconds()
    totalProcessed := s.stats.ProcessedFiles
    failedFiles := s.stats.FailedFiles
    s.mu.Unlock()

    timeColor := color.New(color.FgHiBlack).SprintfFunc()
    timeStr := timeColor("[%s]", time.Now().Format("15:04:05"))

    // Pequena pausa para garantir que todos os logs anteriores foram processados    
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
        fmt.Sprintf("Failed to process %d files", failedFiles))
    
    // Pequena pausa para garantir que as estatísticas foram processadas
    time.Sleep(100 * time.Millisecond)
}
