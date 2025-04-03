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

type LocalScannerConfig struct {
	Concurrency       int
	AllowTestExamples bool
	MaxFileSize       int64
	ProcessBinaryFiles bool
}

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

func NewLocalScanner(
	patternManager *patterns.PatternManager,
	writer *output.Writer,
	logger *output.Logger,
	config LocalScannerConfig,
) *LocalScanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	if config.Concurrency <= 0 {
		config.Concurrency = 10
	}
	
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = 10 * 1024 * 1024
	}
	
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

/* 
   Scans a list of files for secrets and returns error information
*/
func (s *LocalScanner) ScanFiles(files []string) error {
	s.mu.Lock()
	s.stats = LocalScanStats{
		TotalFiles: len(files),
		StartTime:  time.Now(),
	}
	s.mu.Unlock()
	
	uniqueFiles := s.getUniqueAndSortedFiles(files)
	
	s.logger.Info("Found %d local files to scan", len(uniqueFiles))
	
	progressBar := output.NewProgressBar(len(uniqueFiles), 40)
	progressBar.SetPrefix("Processing: ")
	
	s.logger.SetProgressBar(progressBar)
	
	progressBar.Start()
	progressBar.Update(0)
	progressBar.SetSuffix("Secrets: 0 | Rate: 0.0/s")
	
	time.Sleep(50 * time.Millisecond)
	
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
				
				progressBar.Update(processedCount)
				progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s",
					secretsFound,
					float64(processedCount)/time.Since(s.stats.StartTime).Seconds()))
				
			case <-done:
				return
			}
		}
	}()
	
	var wg sync.WaitGroup
	resultChan := make(chan int, len(uniqueFiles))
	errorChan := make(chan error, len(uniqueFiles))
	
	sem := make(chan struct{}, s.config.Concurrency)
	
	for _, file := range uniqueFiles {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			
			sem <- struct{}{}
			defer func() { <-sem }()
			
			secretCount, err := s.processFile(filePath)
			
			s.mu.Lock()
			s.stats.ProcessedFiles++
			s.mu.Unlock()
			
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- secretCount
			}
		}(file)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
		
		s.mu.Lock()
		if tickerRunning {
			tickerRunning = false
			close(done)
		}
		s.mu.Unlock()
	}()
	
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
	
	s.mu.Lock()
	if tickerRunning {
		tickerRunning = false
		close(done)
	}
	s.mu.Unlock()
	
	progressBar.Stop()
	progressBar.Finalize()
	
	s.logger.SetProgressBar(nil)
	
	s.logger.Flush()
	time.Sleep(50 * time.Millisecond)
	
	s.logFinalStats()
	
	if len(errorList) > 0 {
		return fmt.Errorf("encountered %d errors during scanning, first error: %v",
			len(errorList), errorList[0])
	}
	
	return nil
}

/* 
   Processes a single file by checking its size, content and searching for secrets
*/
func (s *LocalScanner) processFile(filePath string) (int, error) {
	select {
	case <-s.ctx.Done():
		return 0, fmt.Errorf("processing interrupted")
	default:
	}
	
	fi, err := os.Stat(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("cannot access file %s: %v", filePath, err)
	}
	
	if fi.IsDir() {
		s.incrementSkippedFiles()
		return 0, nil
	}
	
	if fi.Size() > s.config.MaxFileSize {
		s.incrementSkippedFiles()
		s.logger.Debug("Skipping large file: %s (size: %d bytes)", filePath, fi.Size())
		return 0, nil
	}
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	
	if !s.config.ProcessBinaryFiles && utils.IsBinaryContent(content) {
		s.incrementSkippedFiles()
		s.logger.Debug("Skipping binary content in file: %s", filePath)
		return 0, nil
	}
	
	s.logger.Debug("Processing file: %s (size: %d bytes)", filePath, len(content))
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	fileURL := "file://" + filepath.ToSlash(absPath)
	
	secrets, err := s.detector.DetectSecrets(string(content), fileURL)
	if err != nil {
		s.incrementFailedFiles()
		s.logger.Error("Failed to process file %s: %v", filePath, err)
		return 0, err
	}
	
	for i := range secrets {
		if secrets[i].Line == 0 {
			secrets[i].Line = utils.FindLineNumber(string(content), secrets[i].Value)
		}
	}
	
	for _, secret := range secrets {
		locationURL := fmt.Sprintf("%s#L%d", fileURL, secret.Line)
		
		s.logger.SecretFound(secret.Type, secret.Value, locationURL)
		
		if s.writer != nil {
			err := s.writer.WriteSecret(secret.Type, secret.Value, locationURL, secret.Context, secret.Line)
			if err != nil {
				s.logger.Error("Failed to write secret to output: %v", err)
			}
		}
	}
	
	if len(secrets) > 0 {
		s.logger.Success("Found %d secrets in %s", len(secrets), filePath)
	} else {
		s.logger.Debug("No secrets found in %s", filePath)
	}
	
	s.mu.Lock()
	s.stats.TotalSecrets += len(secrets)
	s.stats.TotalBytes += fi.Size()
	s.mu.Unlock()
	
	return len(secrets), nil
}

/* 
   Returns a deduplicated and sorted list of files for deterministic processing
*/
func (s *LocalScanner) getUniqueAndSortedFiles(files []string) []string {
	uniqueMap := make(map[string]bool)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err == nil {
			uniqueMap[absPath] = true
		} else {
			uniqueMap[file] = true
		}
	}
	
	uniqueFiles := make([]string, 0, len(uniqueMap))
	for file := range uniqueMap {
		uniqueFiles = append(uniqueFiles, file)
	}
	
	sort.Strings(uniqueFiles)
	
	return uniqueFiles
}

func (s *LocalScanner) incrementFailedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.FailedFiles++
}

func (s *LocalScanner) incrementSkippedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.SkippedFiles++
}

/* 
   Outputs the final scanning statistics to the console
*/
func (s *LocalScanner) logFinalStats() {
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
	
	time.Sleep(100 * time.Millisecond)
}

func (s *LocalScanner) GetStats() LocalScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	return s.stats
}

func (s *LocalScanner) Cleanup() {
	s.cancelFunc()
}
