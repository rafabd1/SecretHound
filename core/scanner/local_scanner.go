package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

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
	NoProgress        bool
	Silent            bool
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
   Scans a list of files for secrets and returns stats and error information
*/
func (s *LocalScanner) ScanFiles(files []string) (LocalScanStats, error) {
	s.mu.Lock()
	s.stats = LocalScanStats{
		TotalFiles: len(files),
		StartTime:  time.Now(),
	}
	s.mu.Unlock()
	
	uniqueFiles := s.getUniqueAndSortedFiles(files)
	
	if !s.config.Silent {
		s.logger.Info("Scanning %d local files...", len(uniqueFiles))
	}
	
	var progressBar *output.ProgressBar
	if !s.config.NoProgress && !s.config.Silent {
		progressBar = output.NewProgressBar(len(uniqueFiles), 40)
		progressBar.SetPrefix("Scanning Files: ")
		s.logger.SetProgressBar(progressBar)
		progressBar.Start()
		progressBar.Update(0)
		progressBar.SetSuffix("Secrets: 0 | Rate: 0.0/s")
	}
	
	time.Sleep(50 * time.Millisecond)
	
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	done := make(chan struct{})
	tickerRunning := true
	
	if progressBar != nil {
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
					currentTotalSecrets := s.stats.TotalSecrets
					startTime := s.stats.StartTime
					s.mu.Unlock()
					
					progressBar.Update(processedCount)
					rate := 0.0
					duration := time.Since(startTime).Seconds()
					if duration > 0 {
						rate = float64(processedCount) / duration
					}
					progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s", currentTotalSecrets, rate))
					
				case <-done:
					return
				}
			}
		}()
	}
	
	var wg sync.WaitGroup
	errorChan := make(chan error, len(uniqueFiles))
	
	sem := make(chan struct{}, s.config.Concurrency)
	
	for _, file := range uniqueFiles {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			
			sem <- struct{}{}
			defer func() { <-sem }()
			
			_, err := s.processFile(filePath)
			
			if err != nil {
				errorChan <- err
			}
		}(file)
	}
	
	go func() {
		wg.Wait()
		close(errorChan)
		
		s.mu.Lock()
		if tickerRunning && progressBar != nil {
			tickerRunning = false
			close(done)
		}
		s.mu.Unlock()
	}()
	
	var errorList []error
	filesProcessed := 0
	
	for err := range errorChan {
		errorList = append(errorList, err)
		filesProcessed++
	}
	
	s.mu.Lock()
	if tickerRunning && progressBar != nil {
		tickerRunning = false
		close(done)
	}
	s.mu.Unlock()
	
	if progressBar != nil {
		progressBar.Stop()
		progressBar.Finalize()
		s.logger.SetProgressBar(nil)
	}
	
	s.logger.Flush()
	time.Sleep(50 * time.Millisecond)
	
	s.mu.Lock()
	s.stats.EndTime = time.Now()
	finalStats := s.stats
	s.mu.Unlock()
	
	if len(errorList) > 0 {
		return finalStats, fmt.Errorf("encountered %d errors during scanning, first error: %v",
			len(errorList), errorList[0])
	}
	
	return finalStats, nil
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
		if !s.config.Silent {
			s.logger.Debug("Skipping large file: %s (%d bytes)", filePath, fi.Size())
		}
		return 0, nil
	}
	
	isBinary := utils.IsBinaryFile(filePath)
	if isBinary && !s.config.ProcessBinaryFiles {
		s.incrementSkippedFiles()
		if !s.config.Silent {
			s.logger.Debug("Skipping binary file: %s", filePath)
		}
		return 0, nil
	}
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	
	fileURL := "file://" + filepath.ToSlash(filePath)
	secrets, err := s.detector.DetectSecrets(string(content), fileURL)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("error detecting secrets in %s: %v", filePath, err)
	}
	
	secretCount := len(secrets)
	if secretCount > 0 {
		s.mu.Lock()
		s.stats.TotalSecrets += secretCount
		s.stats.TotalBytes += fi.Size()
		s.mu.Unlock()
		if s.writer != nil {
			for _, sec := range secrets {
				if err := s.writer.WriteSecret(sec.URL, sec.Type, sec.Value, sec.URL, sec.Context, sec.Description, sec.Line); err != nil {
					s.logger.Error("Failed to write secret to output: %v", err)
				}
			}
		}
	}
	
	s.mu.Lock()
	s.stats.ProcessedFiles++
	s.mu.Unlock()
	
	return secretCount, nil
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

func (s *LocalScanner) GetStats() LocalScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	return s.stats
}

func (s *LocalScanner) Cleanup() {
	s.cancelFunc()
}
