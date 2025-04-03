package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

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

type LocalScannerStats struct {
	TotalFiles     int
	ProcessedFiles int
	FailedFiles    int
	TotalSecrets   int
	TotalBytes     int64
	StartTime      time.Time
	EndTime        time.Time
}

func NewLocalScanner(processor *Processor, writer *output.Writer, logger *output.Logger) *LocalScanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LocalScanner{
		processor:   processor,
		writer:      writer,
		logger:      logger,
		concurrency: 10,
		stats: LocalScannerStats{
			StartTime: time.Now(),
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

func (s *LocalScanner) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

func (s *LocalScanner) ScanFiles(files []string) error {
	executionID := GetUniqueExecutionID()
	s.logger.Debug("Started scan execution #%d with %d files", executionID, len(files))
	
	s.processor.CompleteReset()
	s.logger.ResetState()
	
	err := s.processor.InitializeRegexManager()
	if err != nil {
		return fmt.Errorf("failed to initialize RegexManager: %w", err)
	}
	s.logger.Debug("Initialized RegexManager with %d patterns", s.processor.GetRegexPatternCount())
	
	s.mu.Lock()
	s.stats = LocalScannerStats{
		TotalFiles: len(files),
		StartTime: time.Now(),
	}
	s.mu.Unlock()
	
	uniqueFiles := s.getUniqueAndSortedFiles(files)
	files = uniqueFiles
	
	s.mu.Lock()
	s.stats.TotalFiles = len(files)
	s.stats.StartTime = time.Now()
	s.mu.Unlock()

	s.logger.Info("Found %d local files to scan", len(files))

	progressBar := output.NewProgressBar(len(files), 40)
	progressBar.SetPrefix("Processing: ")
	
	s.logger.SetProgressBar(progressBar)
	
	progressBar.Start()
	
	progressBar.Update(0)
	progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: 0.0/s", 0))
	
	time.Sleep(50 * time.Millisecond)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

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
	resultChan := make(chan int, len(files))
	errorChan := make(chan error, len(files))
	
	sem := make(chan struct{}, s.concurrency)
	
	for _, file := range files {
		filePath := file
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			count, err := s.processFile(filePath)
			
			s.mu.Lock()
			s.stats.ProcessedFiles++
			processedCount := s.stats.ProcessedFiles
			s.mu.Unlock()
			
			progressBar.Update(processedCount)
			
			if err != nil {
				errorChan <- err
			} else {
				resultChan <- count
			}
		}()
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
		
		s.mu.Lock()
		if !tickerDone {
			tickerDone = true
			close(done)
		}
		s.mu.Unlock()
	}()
	
	secretsFound := 0
	var errorList []error
	
	filesProcessed := 0
	totalFiles := len(files)
	
	for filesProcessed < totalFiles {
		select {
		case res, ok := <-resultChan:
			if (!ok) {
				continue
			}
			secretsFound += res
			filesProcessed++
		case err, ok := <-errorChan:
			if (!ok) {
				continue
			}
			errorList = append(errorList, err)
			filesProcessed++
		}
	}
	
	s.mu.Lock()
	if !tickerDone {
		tickerDone = true
		close(done)
	}
	s.mu.Unlock()
	
	progressBar.Stop()
	progressBar.Finalize()
	
	s.logger.SetProgressBar(nil)
	
	if s.logger != nil {
		s.logger.Flush()
		time.Sleep(50 * time.Millisecond)
	}
	
	s.logFinalStats()
	
	if len(errorList) > 0 {
		return fmt.Errorf("encountered %d errors during local file scanning, first error: %v", 
			len(errorList), errorList[0])
	}
	
	return nil
}

/* 
   Removes duplicates and sorts files to ensure deterministic processing order
*/
func (s *LocalScanner) getUniqueAndSortedFiles(files []string) []string {
	uniqueFilesMap := make(map[string]bool)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err == nil {
			uniqueFilesMap[absPath] = true
		} else {
			uniqueFilesMap[file] = true
		}
	}
	
	uniqueFiles := make([]string, 0, len(uniqueFilesMap))
	for file := range uniqueFilesMap {
		uniqueFiles = append(uniqueFiles, file)
	}
	
	sort.Strings(uniqueFiles)
	
	return uniqueFiles
}

func (s *LocalScanner) processFile(filePath string) (int, error) {
	select {
	case <-s.ctx.Done():
		return 0, fmt.Errorf("processing interrupted")
	default:
	}
	
	fi, err := os.Stat(filePath)
	if (err != nil) {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("cannot access file %s: %v", filePath, err)
	}
	
	if fi.IsDir() {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("%s is a directory, not a file", filePath)
	}
	
	if fi.Size() > 10*1024*1024 {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("file %s is too large (> 10MB)", filePath)
	}
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.incrementFailedFiles()
		return 0, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	
	if utils.IsBinaryContent(content) {
		s.incrementProcessedFiles()
		s.logger.Debug("Skipping binary content in file: %s", filePath)
		return 0, nil
	}
	
	s.logger.Debug("Processing local file: %s (size: %d bytes)", filePath, len(content))
	
	fileContent := string(content)
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	localURL := "file://" + filepath.ToSlash(absPath)
	
	s.logger.Debug("Scanning local file with URL: %s", localURL)
	
	if s.logger.IsVerbose() {
		ext := utils.GetFileExtension(filePath)
		s.logger.Debug("File details: %s, extension: %s, size: %d bytes", filepath.Base(filePath), ext, len(content))
	}
	
	if s.processor.regexManager == nil || s.processor.regexManager.GetPatternCount() == 0 {
		s.logger.Debug("RegexManager não inicializado. Inicializando para arquivo local...")
		err := s.processor.InitializeRegexManager()
		if err != nil {
			s.logger.Error("Failed to initialize RegexManager: %v", err)
			return 0, err
		}
		
		s.processor.regexManager.InjectDefaultPatternsDirectly()
		s.logger.Debug("Padrões regex injetados diretamente: %d padrões", 
					  s.processor.regexManager.GetPatternCount())
	}
	
	s.processor.regexManager.SetLocalFileMode(true)
	
	secrets, err := s.processor.ProcessJSContent(fileContent, localURL)
	
	s.processor.regexManager.SetLocalFileMode(false)
	
	if err != nil {
		s.incrementFailedFiles()
		s.logger.Error("Failed to process file %s: %v", filePath, err)
		return 0, err
	}
	
	s.logger.Debug("Found %d secrets in file %s", len(secrets), filePath)
	
	enhancedSecrets := make([]Secret, 0, len(secrets))
	for _, secret := range secrets {
		if secret.Line == 0 {
			secret.Line = utils.FindLineNumber(fileContent, secret.Value)
		}
		
		if len(secret.Context) < 60 && secret.Line > 0 {
			lines := strings.Split(fileContent, "\n")
			if secret.Line <= len(lines) {
				startLine := max(0, secret.Line-2)
				endLine := min(len(lines), secret.Line+2)
				enhancedContext := strings.Join(lines[startLine:endLine], "\n")
				if len(enhancedContext) > len(secret.Context) {
					secret.Context = enhancedContext
				}
			}
		}
		
		enhancedSecrets = append(enhancedSecrets, secret)
	}
	
	secrets = enhancedSecrets
	
	for _, secret := range secrets {
		locationURL := fmt.Sprintf("%s#L%d", localURL, secret.Line)
		
		s.logger.SecretFound(secret.Type, secret.Value, locationURL)
		
		if s.writer != nil {
			err := s.writer.WriteSecret(secret.Type, secret.Value, locationURL, secret.Context, secret.Line)
			if err != nil {
				s.logger.Error("Failed to write secret from file %s to output: %v", filePath, err)
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *LocalScanner) incrementProcessedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ProcessedFiles++
}

func (s *LocalScanner) incrementFailedFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.FailedFiles++
	s.stats.ProcessedFiles++
}

func (s *LocalScanner) GetStats() LocalScannerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	statsCopy := s.stats
	return statsCopy
}

func (s *LocalScanner) Cleanup() {
	s.cancelFunc()
}

func (s *LocalScanner) logFinalStats() {
	s.mu.Lock()
	s.stats.EndTime = time.Now()
	duration := s.stats.EndTime.Sub(s.stats.StartTime)
	filesPerSecond := float64(s.stats.ProcessedFiles) / duration.Seconds()
	totalProcessed := s.stats.ProcessedFiles
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
		fmt.Sprintf("Failed to process %d files", failedFiles))
	
	time.Sleep(100 * time.Millisecond)
}
