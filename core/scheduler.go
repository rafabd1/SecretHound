package core

import (
	"context"
	"sync"
	"time"

	"github.com/secrethound/networking"
	"github.com/secrethound/output"
	"github.com/secrethound/utils"
)

// Scheduler manages the balancing of requests between threads
type Scheduler struct {
	domainManager *networking.DomainManager
	client        *networking.Client
	processor     *Processor
	writer        *output.Writer
	logger        *output.Logger
	workerPool    *utils.WorkerPool
	concurrency   int
	mutex         sync.Mutex
	waitingURLs   []string
	ctx           context.Context
	cancel        context.CancelFunc
	waitGroup     sync.WaitGroup
	stats         SchedulerStats
}

// SchedulerStats contains statistics about the scheduler's operation
type SchedulerStats struct {
	TotalURLs        int
	ProcessedURLs    int
	FailedURLs       int
	BlockedDomains   int
	TotalSecrets     int
	StartTime        time.Time
	EndTime          time.Time
	RateLimitHits    int
	WAFBlockHits     int
	DomainRetries    map[string]int
}

// NewScheduler creates a new scheduler instance
func NewScheduler(domainManager *networking.DomainManager, client *networking.Client, 
	processor *Processor, writer *output.Writer, logger *output.Logger) *Scheduler {
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scheduler{
		domainManager: domainManager,
		client:        client,
		processor:     processor,
		writer:        writer,
		logger:        logger,
		concurrency:   10, // Default, will be overridden by Schedule
		ctx:           ctx,
		cancel:        cancel,
		stats: SchedulerStats{
			DomainRetries: make(map[string]int),
			StartTime:     time.Now(),
		},
	}
}

// Schedule distributes URLs among worker threads
func (s *Scheduler) Schedule(urls []string) error {
	s.mutex.Lock()
	s.stats.TotalURLs = len(urls)
	s.stats.StartTime = time.Now()
	s.waitingURLs = urls
	s.mutex.Unlock()
	
	s.logger.Info("Starting to schedule %d URLs for processing", len(urls))
	
	// Create a worker pool with the configured concurrency
	s.workerPool = utils.NewWorkerPool(s.concurrency, len(urls))
	
	// Start worker goroutines
	for i := 0; i < s.concurrency; i++ {
		s.waitGroup.Add(1)
		go s.worker(i)
	}
	
	// Wait for all workers to complete
	s.waitGroup.Wait()
	
	// Record end time and log summary
	s.mutex.Lock()
	s.stats.EndTime = time.Now()
	duration := s.stats.EndTime.Sub(s.stats.StartTime)
	urlsPerSecond := float64(s.stats.ProcessedURLs) / duration.Seconds()
	s.mutex.Unlock()
	
	s.logger.Info("Processing completed in %.2f seconds", duration.Seconds())
	s.logger.Info("Processed %d URLs (%.2f URLs/second)", s.stats.ProcessedURLs, urlsPerSecond)
	s.logger.Info("Found %d secrets", s.stats.TotalSecrets)
	s.logger.Info("Failed to process %d URLs", s.stats.FailedURLs)
	s.logger.Info("Encountered rate limiting %d times", s.stats.RateLimitHits)
	s.logger.Info("Encountered WAF blocks %d times", s.stats.WAFBlockHits)
	
	return nil
}

// worker is a goroutine that processes URLs
func (s *Scheduler) worker(id int) {
	defer s.waitGroup.Done()
	
	s.logger.Debug("Worker %d started", id)
	
	for {
		// Check if context is canceled
		select {
		case <-s.ctx.Done():
			s.logger.Debug("Worker %d stopping due to cancellation", id)
			return
		default:
			// Continue processing
		}
		
		// Get the next URL to process
		url, ok := s.GetNextURL()
		if !ok {
			s.logger.Debug("Worker %d stopping: no more URLs to process", id)
			return
		}
		
		// Extract domain from URL
		domain, err := utils.ExtractDomain(url)
		if (err != nil) {
			s.logger.Warning("Worker %d: failed to extract domain from URL %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		// Check if domain is blocked
		if s.domainManager.IsBlocked(domain) {
			s.logger.Debug("Worker %d: domain %s is blocked, requeueing URL %s", id, domain, url)
			s.requeueURL(url)
			time.Sleep(100 * time.Millisecond) // Small delay to prevent busy-waiting
			continue
		}
		
		// Fetch and process the content
		s.logger.Debug("Worker %d: processing URL %s", id, url)
		content, err := s.client.GetJSContent(url)
		
		if err != nil {
			if s.handleRequestError(err, domain, url) {
				// URL has been requeued or domain blocked, continue
				continue
			}
			
			// Fatal error, log and mark as failed
			s.logger.Error("Worker %d: failed to fetch content from %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		// Process the content
		secrets, err := s.processor.ProcessJSContent(content, url)
		if err != nil {
			s.logger.Error("Worker %d: failed to process content from %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		// Write secrets to output file if configured
		if s.writer != nil && len(secrets) > 0 {
			for _, secret := range secrets {
				err := s.writer.WriteSecret(secret.Type, secret.Value, secret.URL, secret.Context, secret.Line)
				if err != nil {
					s.logger.Error("Worker %d: failed to write secret to output file: %v", id, err)
				}
			}
		}
		
		// Update stats
		s.mutex.Lock()
		s.stats.ProcessedURLs++
		s.stats.TotalSecrets += len(secrets)
		s.mutex.Unlock()
		
		s.logger.Info("Worker %d: processed URL %s, found %d secrets", id, url, len(secrets))
	}
}

// handleRequestError handles errors during content fetching
func (s *Scheduler) handleRequestError(err error, domain, url string) bool {
	// Check if error is caused by rate limiting
	if utils.IsRateLimitError(err) {
		s.mutex.Lock()
		s.stats.RateLimitHits++
		s.mutex.Unlock()
		
		s.logger.Warning("Domain %s is being rate limited, adding to blocked list", domain)
		
		// Add domain to blocked list for a few minutes
		blockDuration := time.Duration(2+s.getDomainRetryCount(domain)) * time.Minute
		s.domainManager.AddBlockedDomain(domain, blockDuration)
		s.incrementDomainRetry(domain)
		
		// Requeue the URL for later processing
		s.requeueURL(url)
		return true
	}
	
	// Check if error is caused by WAF
	if utils.IsWAFError(err) {
		s.mutex.Lock()
		s.stats.WAFBlockHits++
		s.mutex.Unlock()
		
		s.logger.Warning("Domain %s is blocking with WAF, adding to blocked list", domain)
		
		// Add domain to blocked list for longer
		blockDuration := time.Duration(5+s.getDomainRetryCount(domain)*2) * time.Minute
		s.domainManager.AddBlockedDomain(domain, blockDuration)
		s.incrementDomainRetry(domain)
		
		// Requeue the URL for later processing
		s.requeueURL(url)
		return true
	}
	
	// For temporary network errors, retry
	if utils.IsTemporaryError(err) {
		s.logger.Debug("Temporary error for domain %s, will retry URL %s", domain, url)
		s.requeueURL(url)
		return true
	}
	
	// For other errors, don't retry
	return false
}

// getDomainRetryCount gets the number of retries for a domain
func (s *Scheduler) getDomainRetryCount(domain string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stats.DomainRetries[domain]
}

// incrementDomainRetry increments the retry count for a domain
func (s *Scheduler) incrementDomainRetry(domain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.DomainRetries[domain]++
}

// incrementFailedURLs increments the count of failed URLs
func (s *Scheduler) incrementFailedURLs() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.FailedURLs++
	s.stats.ProcessedURLs++ // Still count as processed for total tracking
}

// AddBlockedDomain adds a domain to the waiting list
func (s *Scheduler) AddBlockedDomain(domain string) {
	s.logger.Debug("Adding domain to blocked list: %s", domain)
	s.domainManager.AddBlockedDomain(domain, 5*time.Minute)
}

// GetNextURL gets the next URL to process
func (s *Scheduler) GetNextURL() (string, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if len(s.waitingURLs) == 0 {
		return "", false
	}
	
	// Get the next URL
	url := s.waitingURLs[0]
	s.waitingURLs = s.waitingURLs[1:]
	
	return url, true
}

// requeueURL adds a URL back to the waiting list
func (s *Scheduler) requeueURL(url string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Add to the end of the waiting URLs list
	s.waitingURLs = append(s.waitingURLs, url)
}

// GetStats returns current scheduler statistics
func (s *Scheduler) GetStats() SchedulerStats {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Create a copy to avoid race conditions
	statsCopy := SchedulerStats{
		TotalURLs:        s.stats.TotalURLs,
		ProcessedURLs:    s.stats.ProcessedURLs,
		FailedURLs:       s.stats.FailedURLs,
		BlockedDomains:   s.stats.BlockedDomains,
		TotalSecrets:     s.stats.TotalSecrets,
		StartTime:        s.stats.StartTime,
		EndTime:          s.stats.EndTime,
		RateLimitHits:    s.stats.RateLimitHits,
		WAFBlockHits:     s.stats.WAFBlockHits,
		DomainRetries:    make(map[string]int),
	}
	
	// Copy the domain retries map
	for domain, count := range s.stats.DomainRetries {
		statsCopy.DomainRetries[domain] = count
	}
	
	return statsCopy
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.logger.Info("Stopping scheduler")
	s.cancel()
}

// SetConcurrency sets the number of concurrent workers
func (s *Scheduler) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

// GetActiveWorkers returns the number of active workers
func (s *Scheduler) GetActiveWorkers() int {
	if s.workerPool != nil {
		return s.workerPool.ActiveJobs()
	}
	return 0
}
