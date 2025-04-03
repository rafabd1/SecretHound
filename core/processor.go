package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
	cacheService *CacheService
	mu           sync.Mutex
	stats        ProcessorStats
}

type ProcessorStats struct {
	FilesProcessed  int
	SecretsFound    int
	ProcessingTime  time.Duration
	FailedFiles     int
	TotalBytesRead  int64
}

func NewProcessor(regexManager *RegexManager, logger *output.Logger) *Processor {
	processor := &Processor{
		regexManager: regexManager,
		logger:       logger,
		cacheService: NewCacheService(),
		stats: ProcessorStats{
			FilesProcessed: 0,
			SecretsFound:   0,
		},
	}
	
	RegisterProcessor(processor)
	
	return processor
}

/* 
   Ensures the RegexManager has patterns loaded and is ready for use
*/
func (p *Processor) InitializeRegexManager() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.regexManager = NewRegexManager()
	
	err := p.regexManager.LoadPredefinedPatterns()
	if (err != nil) {
		p.logger.Error("Failed to load patterns: %v", err)
		return err
	}
	
	p.logger.Debug("Successfully initialized RegexManager with %d patterns", p.regexManager.GetPatternCount())
	return nil
}

func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
	if p.regexManager == nil || p.regexManager.GetPatternCount() == 0 {
		err := p.InitializeRegexManager()
		if err != nil {
			p.logger.Error("Failed to initialize RegexManager: %v", err)
			return nil, utils.NewError(utils.ConfigError, "RegexManager initialization failed", err)
		}
	}

	startTime := time.Now()
	p.logger.Debug("Processing content from URL: %s", url)

	isLocalFile := strings.HasPrefix(url, "file://")
	if isLocalFile {
		p.logger.Debug("Processing local file with %d patterns and %d bytes", 
			p.regexManager.GetPatternCount(), len(content))
			
		p.regexManager.SetLocalFileMode(true)
		defer p.regexManager.SetLocalFileMode(false)
	}

	var secrets []Secret
	var err error
	
	if isLocalFile {
		patternMatches := p.regexManager.FindMatches(content, url)
		
		for patternName, matches := range patternMatches {
			for _, match := range matches {
				context := extractContext(content, match)
				lineNum := utils.FindLineNumber(content, match)
				
				secret := Secret{
					Type:    patternName,
					Value:   match,
					Context: context,
					URL:     url,
					Line:    lineNum,
				}
				secrets = append(secrets, secret)
			}
		}
	} else {
		secrets, err = p.regexManager.FindSecrets(content, url)
		if err != nil {
			p.mu.Lock()
			p.stats.FailedFiles++
			p.mu.Unlock()
			return nil, utils.NewError(utils.ProcessingError, fmt.Sprintf("failed to process content from %s", url), err)
		}
	}
	
	p.cacheService.StoreSecrets(content, secrets)

	p.mu.Lock()
	p.stats.FilesProcessed++
	p.stats.SecretsFound += len(secrets)
	p.stats.TotalBytesRead += int64(len(content))
	p.stats.ProcessingTime += time.Since(startTime)
	p.mu.Unlock()

	p.logger.Debug("Found %d secrets in %s (took %v)", 
		len(secrets), url, time.Since(startTime))
	
	return secrets, nil
}

/* 
   Extracts surrounding context from content around a matching string
*/
func extractContext(content, match string) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return ""
	}

	contextStart := max(0, idx-100)
	contextEnd := min(len(content), idx+len(match)+100)
	
	return content[contextStart:contextEnd]
}

func (p *Processor) ProcessJSStream(ctx context.Context, reader io.Reader, url string) ([]Secret, error) {
	var builder strings.Builder
	buffer := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return nil, utils.NewError(utils.ProcessingError, "processing canceled", ctx.Err())
		default:
		}

		n, err := reader.Read(buffer)
		if n > 0 {
			builder.Write(buffer[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, utils.NewError(utils.ProcessingError, "error reading content stream", err)
		}
	}

	return p.ProcessJSContent(builder.String(), url)
}

func (p *Processor) GetStats() ProcessorStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.stats
}

func (p *Processor) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats = ProcessorStats{}
}

func (p *Processor) CompleteReset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.regexManager != nil {
		p.regexManager.CompleteReset()
	}
	
	p.regexManager = NewRegexManager()
	p.cacheService = NewCacheService()
	
	p.stats = ProcessorStats{
		FilesProcessed: 0,
		SecretsFound:   0,
		ProcessingTime: 0,
		FailedFiles:    0,
		TotalBytesRead: 0,
	}
}

func (p *Processor) BatchProcess(contents map[string]string, concurrency int) (map[string][]Secret, error) {
	results := make(map[string][]Secret)
	resultsMu := sync.Mutex{}
	errors := make([]error, 0)
	errorsMu := sync.Mutex{}

	pool := utils.NewWorkerPool(concurrency, len(contents))

	for url, content := range contents {
		url := url
		content := content

		pool.Submit(func() (interface{}, error) {
			secrets, err := p.ProcessJSContent(content, url)
			if err != nil {
				return nil, err
			}

			return struct {
				URL     string
				Secrets []Secret
			}{
				URL:     url,
				Secrets: secrets,
			}, nil
		})
	}

	for result := range pool.Results() {
		r := result.(struct {
			URL     string
			Secrets []Secret
		})

		resultsMu.Lock()
		results[r.URL] = r.Secrets
		resultsMu.Unlock()
	}

	for err := range pool.Errors() {
		errorsMu.Lock()
		errors = append(errors, err)
		errorsMu.Unlock()
	}

	pool.Wait()

	if len(errors) > 0 {
		return results, errors[0]
	}

	return results, nil
}

func (p *Processor) GetRegexPatternCount() int {
	if p.regexManager != nil {
		return p.regexManager.GetPatternCount()
	}
	return 0
}
