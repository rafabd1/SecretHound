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

// Processor is responsible for processing JS files and extracting secrets
type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
	cacheService *CacheService
	mu           sync.Mutex
	stats        ProcessorStats
}

// ProcessorStats tracks statistics about the processing
type ProcessorStats struct {
	FilesProcessed  int
	SecretsFound    int
	ProcessingTime  time.Duration
	FailedFiles     int
	TotalBytesRead  int64
}

// NewProcessor creates a new processor instance
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
	
	// Register this processor globally so it can be reset if needed
	RegisterProcessor(processor)
	
	return processor
}

// InitializeRegexManager ensures that RegexManager has patterns loaded
func (p *Processor) InitializeRegexManager() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Always create a fresh instance
    p.regexManager = NewRegexManager()
    
    // Load patterns directly
    p.regexManager.InjectDefaultPatternsDirectly()
    
    p.logger.Debug("Successfully initialized RegexManager with %d patterns", p.regexManager.GetPatternCount())
    return nil
}

// ProcessJSContent processes JavaScript content and extracts secrets
func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
    // Initialize RegexManager if needed
    if p.regexManager == nil || p.regexManager.GetPatternCount() == 0 {
        err := p.InitializeRegexManager()
        if err != nil {
            p.logger.Error("Failed to initialize RegexManager: %v", err)
            return nil, utils.NewError(utils.ConfigError, "RegexManager initialization failed", err)
        }
    }

    startTime := time.Now()
    p.logger.Debug("Processing content from URL: %s", url)

    // Use the regex manager to find secrets in the content
    var secrets []Secret
    var err error
    secrets, err = p.regexManager.FindSecrets(content, url)
    
    if err != nil {
        p.mu.Lock()
        p.stats.FailedFiles++
        p.mu.Unlock()
        return nil, utils.NewError(utils.ProcessingError, fmt.Sprintf("failed to process content from %s", url), err)
    }
    
    // DIAGNÓSTICO: Pular todo o filtro adicional
    filteredSecrets := secrets
    
    // Store in cache for future use
    p.cacheService.StoreSecrets(content, filteredSecrets)

    // Update stats
    p.mu.Lock()
    p.stats.FilesProcessed++
    p.stats.SecretsFound += len(filteredSecrets)
    p.stats.TotalBytesRead += int64(len(content))
    p.stats.ProcessingTime += time.Since(startTime)
    p.mu.Unlock()

    return filteredSecrets, nil
}


// ProcessJSStream processes a JavaScript content stream and extracts secrets
func (p *Processor) ProcessJSStream(ctx context.Context, reader io.Reader, url string) ([]Secret, error) {
	var builder strings.Builder
	buffer := make([]byte, 4096)

	for {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return nil, utils.NewError(utils.ProcessingError, "processing canceled", ctx.Err())
		default:
			// Continue processing
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

// GetStats returns the current processor stats
func (p *Processor) GetStats() ProcessorStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.stats
}

// ResetStats resets the processor stats
func (p *Processor) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats = ProcessorStats{}
}

// CompleteReset completely resets the processor to a clean initial state
func (p *Processor) CompleteReset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Create a fresh RegexManager
	if p.regexManager != nil {
		p.regexManager.CompleteReset()
	}
	
	// Set a brand new RegexManager
	p.regexManager = NewRegexManager()
	
	// Reset the cache service
	p.cacheService = NewCacheService()
	
	// Reset stats
	p.stats = ProcessorStats{
		FilesProcessed: 0,
		SecretsFound:   0,
		ProcessingTime: 0,
		FailedFiles:    0,
		TotalBytesRead: 0,
	}
}

// BatchProcess processes multiple content strings in parallel
func (p *Processor) BatchProcess(contents map[string]string, concurrency int) (map[string][]Secret, error) {
	results := make(map[string][]Secret)
	resultsMu := sync.Mutex{}
	errors := make([]error, 0)
	errorsMu := sync.Mutex{}

	// Create a worker pool
	pool := utils.NewWorkerPool(concurrency, len(contents))

	// Add jobs to the pool
	for url, content := range contents {
		url := url     // Create local copy for closure
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

	// Process results
	for result := range pool.Results() {
		r := result.(struct {
			URL     string
			Secrets []Secret
		})

		resultsMu.Lock()
		results[r.URL] = r.Secrets
		resultsMu.Unlock()
	}

	// Process errors
	for err := range pool.Errors() {
		errorsMu.Lock()
		errors = append(errors, err)
		errorsMu.Unlock()
	}

	// Wait for all jobs to complete
	pool.Wait()

	// If there were errors, return the first one
	if len(errors) > 0 {
		return results, errors[0]
	}

	return results, nil
}

// GetRegexPatternCount returns the count of regex patterns
func (p *Processor) GetRegexPatternCount() int {
	if p.regexManager != nil {
		return p.regexManager.GetPatternCount()
	}
	return 0
}

