package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/secrethound/output"
	"github.com/secrethound/utils"
)

// Processor is responsible for processing JS files and extracting secrets
type Processor struct {
	regexManager *RegexManager
	logger       *output.Logger
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
	return &Processor{
		regexManager: regexManager,
		logger:       logger,
		stats: ProcessorStats{
			FilesProcessed: 0,
			SecretsFound:   0,
		},
	}
}

// ProcessJSContent processes JavaScript content and extracts secrets
func (p *Processor) ProcessJSContent(content string, url string) ([]Secret, error) {
	startTime := time.Now()
	p.logger.Debug("Processing content from URL: %s", url)
	
	// Update processor stats
	p.mu.Lock()
	p.stats.FilesProcessed++
	p.stats.TotalBytesRead += int64(len(content))
	p.mu.Unlock()
	
	// Use the regex manager to find secrets in the content
	secrets, err := p.regexManager.FindSecrets(content, url)
	if err != nil {
		p.mu.Lock()
		p.stats.FailedFiles++
		p.mu.Unlock()
		return nil, utils.NewError(utils.ProcessingError, fmt.Sprintf("failed to process content from %s", url), err)
	}
	
	// Log each found secret
	for _, secret := range secrets {
		p.logger.SecretFound(secret.Type, secret.Value, secret.URL)
	}
	
	// Update stats
	p.mu.Lock()
	p.stats.SecretsFound += len(secrets)
	p.stats.ProcessingTime += time.Since(startTime)
	p.mu.Unlock()
	
	return secrets, nil
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

// Secret represents a discovered secret
type Secret struct {
	Type     string
	Value    string
	URL      string
	Line     int
	Context  string
}

// String returns a string representation of the secret
func (s Secret) String() string {
	return fmt.Sprintf("[%s] %s (URL: %s, Line: %d, Context: %s)", 
		s.Type, s.Value, s.URL, s.Line, s.Context)
}
