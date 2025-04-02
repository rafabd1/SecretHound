package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/networking"
	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
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
	domainLastAccess *utils.SafeMap[string, time.Time]
	domainCooldown time.Duration
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
			domainLastAccess: utils.NewSafeMap[string, time.Time](),
			domainCooldown: 500 * time.Millisecond, // Internal cooldown between requests to the same domain
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
		s.mutex.Unlock()

		// Group URLs by domain before scheduling
		s.domainManager.GroupURLsByDomain(urls)
		domains := s.domainManager.GetDomainList()
		
		// Build the balanced work queue without redundant logging
		s.buildBalancedWorkQueue(domains)

		// Removendo o log redundante do rate limit, já que agora ele é mostrado nas estatísticas iniciais

		// Critical pause to ensure all initial stats are displayed
		time.Sleep(200 * time.Millisecond)

		// Create and start progress bar
		progressBar := output.NewProgressBar(len(urls), 40)
		progressBar.SetPrefix("Processing: ")

		// Connect progress bar to logger
		s.logger.SetProgressBar(progressBar)

		// Start tracking stats in real-time
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		go func() {
			for {
				select {
				case <-ticker.C:
					s.mutex.Lock()
					processedCount := s.stats.ProcessedURLs
					secretsFound := s.stats.TotalSecrets
					s.mutex.Unlock()

					// Update progress bar
					progressBar.Update(processedCount)

					// Update suffix with statistics
					progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s",
						secretsFound,
						float64(processedCount)/time.Since(s.stats.StartTime).Seconds()))
				case <-s.ctx.Done():
					return
				}
			}
		}()
		
		// Start progress bar AFTER all important info is displayed
		progressBar.Start()

		// Create a worker pool with the configured concurrency
		s.workerPool = utils.NewWorkerPool(s.concurrency, len(urls))

		// Start worker goroutines
		for i := 0; i < s.concurrency; i++ {
			s.waitGroup.Add(1)
			go s.worker(i)
		}

		// Wait for all workers to complete
		s.waitGroup.Wait()

		// Stop the progress bar
		progressBar.Stop()

		// Record end time and log summary
		s.mutex.Lock()
		s.stats.EndTime = time.Now()
		duration := s.stats.EndTime.Sub(s.stats.StartTime)
		urlsPerSecond := float64(s.stats.ProcessedURLs) / duration.Seconds()
		s.mutex.Unlock()

		// Print detailed statistics
		s.logger.Info("Processing completed in %.2f seconds", duration.Seconds())
		s.logger.Info("Processed %d URLs (%.2f URLs/second)", s.stats.ProcessedURLs, urlsPerSecond)
		s.logger.Info("Found %d secrets", s.stats.TotalSecrets)
		s.logger.Info("Failed to process %d URLs", s.stats.FailedURLs)
		s.logger.Info("Encountered rate limiting %d times", s.stats.RateLimitHits)
		s.logger.Info("Encountered WAF blocks %d times", s.stats.WAFBlockHits)

		// Show domain statistics if in verbose mode
		if s.logger.IsVerbose() {
			s.printDomainStatistics()
		}

		return nil
	}

// buildBalancedWorkQueue distributes domains in a balanced way to the work queue
func (s *Scheduler) buildBalancedWorkQueue(domains []string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Clear the waiting URLs queue
	s.waitingURLs = make([]string, 0)
	
	// Calculate the initial URLs to process by taking one URL from each domain
	// to ensure fair distribution across domains
	roundRobinCount := 0
	continueFetching := true
	
	// Sort domains by the number of URLs they have to ensure balanced distribution
	utils.SimpleSortByDomainCount(domains, func(domain string) int {
		return len(s.domainManager.GetURLsForDomain(domain))
	})
	
	for continueFetching {
		continueFetching = false
		
		// Do one pass over all domains
		for _, domain := range domains {
			urls := s.domainManager.GetURLsForDomain(domain)
			
			if roundRobinCount < len(urls) {
				// Add the URL at the current position to the queue
				s.waitingURLs = append(s.waitingURLs, urls[roundRobinCount])
				continueFetching = true
			}
		}
		
		roundRobinCount++
	}
	
	// Shuffle slightly to avoid perfect predictability but maintain domain separation
	s.shuffleWithDomainAwareness(s.waitingURLs)
	
	s.logger.Debug("Built balanced work queue with %d URLs", len(s.waitingURLs))
}

// shuffleWithDomainAwareness shuffles the URLs while trying to keep URLs from same domain separated
func (s *Scheduler) shuffleWithDomainAwareness(urls []string) {
	if len(urls) <= 1 {
		return
	}
	
	// Create a map of domain to list of indices of URLs for that domain
	domainIndices := make(map[string][]int)
	
	// Populate the map
	for i, url := range urls {
		domain, err := utils.ExtractDomain(url)
		if err != nil {
			continue
		}
		
		domainIndices[domain] = append(domainIndices[domain], i)
	}
	
	// Rearrange URLs to spread out domains
	if len(domainIndices) > 1 {
		// Sort domains by the number of URLs they have (descending)
		domains := make([]string, 0, len(domainIndices))
		for domain := range domainIndices {
			domains = append(domains, domain)
		}
		
		utils.SortByValueDesc(domains, func(domain string) int {
			return len(domainIndices[domain])
		})
		
		// Create a new URL queue with better distribution
		newURLs := make([]string, len(urls))
		position := 0
		
		// Place URLs in a round-robin fashion by domain
		for len(domains) > 0 {
			for i := 0; i < len(domains); i++ {
				domain := domains[i]
				indices := domainIndices[domain]
				
				if len(indices) == 0 {
					// Remove this domain as it has no more URLs
					domains = append(domains[:i], domains[i+1:]...)
					i-- // Adjust for the removed domain
					continue
				}
				
				// Place the URL at the current position
				newURLs[position] = urls[indices[0]]
				position++
				
				// Remove the placed URL's index
				domainIndices[domain] = indices[1:]
			}
		}
		
		// Copy back to the original slice
		copy(urls, newURLs)
	}
}

// shouldRequeueDomainURL decides if a domain should be requeued based on its status
func (s *Scheduler) shouldRequeueDomainURL(domain string, worker int) bool {
	if (!s.hasAlternativeURL(domain)) {
		return false
	}
	
	// Check how many requests the domain is subject to (in the queue)
	domainPendingCount := s.countPendingURLsForDomain(domain)
	
	// If there are many pending requests for this domain
	// and there are few unique domains, reduce requeuing
	domainCount := s.domainManager.GetDomainCount()
	if (domainCount <= 3) {
		// For few domains, be less restrictive
		// This avoids excessive requeuing when there are few domains
		return false
	}
	
	// If there are many pending requests, decrease the probability of requeue
	if (domainPendingCount > 5) {
		// Requeue only 20% of the time
		return utils.RandomInt(0, 100) < 20
	}
	
	// Recent access to the domain, but not many pending requests
	// Perform requeue with a 60% probability
	return utils.RandomInt(0, 100) < 60
}

// countPendingURLsForDomain counts how many pending URLs exist for a domain
func (s *Scheduler) countPendingURLsForDomain(targetDomain string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	count := 0
	// Check only the first 50 URLs in the queue for efficiency
	checkLimit := 50
	if (len(s.waitingURLs) < checkLimit) {
		checkLimit = len(s.waitingURLs)
	}
	
	for i := 0; i < checkLimit; i++ {
		if (i >= len(s.waitingURLs)) {
			break
		}
		
		domain, err := utils.ExtractDomain(s.waitingURLs[i])
		if (err == nil && domain == targetDomain) {
			count++
		}
	}
	
	return count
}

// worker is a goroutine that processes URLs
func (s *Scheduler) worker(id int) {
	defer s.waitGroup.Done()
	
	s.logger.Debug("Worker %d started", id)
	
	// Track domains this worker has recently accessed to avoid hammering the same domain
	recentDomains := utils.NewLRUCache(5) // Remember last 5 domains
	
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
		if (!ok) {
			s.logger.Debug("Worker %d stopping: no more URLs to process", id)
			return
		}
		
		// Extract domain from URL
		domain, err := utils.ExtractDomain(url)
		if err != nil {
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
		
		// Check if this domain has a cooldown period
		lastAccess, found := s.domainLastAccess.Get(domain)
		if found && time.Since(lastAccess) < s.domainCooldown {
			// Check if this domain was recently accessed by another worker
			if s.hasAlternativeURL(domain) {
				// Wait a shorter time if requeue is necessary
				time.Sleep(10 * time.Millisecond)
				
				// If there are not enough domains, do not requeue and wait for the cooldown
				if len(s.domainManager.GetDomainList()) <= 3 {
					wait := s.domainCooldown - time.Since(lastAccess)
					if wait > 0 {
						time.Sleep(wait / 2) // Reduce wait time to improve performance
					}
				} else {
					s.requeueURL(url)
					continue
				}
			} else {
				// If there is no alternative, wait until the cooldown passes
				wait := s.domainCooldown - time.Since(lastAccess)
				if wait > 0 {
					time.Sleep(wait)
				}
			}
		}
		
		// Check if this worker has recently accessed this domain 
		if recentDomains.Contains(domain) {
			// Use probabilistic logic instead of always requeueing
			if s.shouldRequeueDomainURL(domain, id) {
				s.logger.Debug("Worker %d: recently accessed domain %s, requeueing URL %s", id, domain, url)
				s.requeueURL(url)
				time.Sleep(20 * time.Millisecond) // Small delay before trying again
				continue
			}
			// Even if recently accessed, proceed if the function returns false
		}
		
		// Track this domain access
		recentDomains.Put(domain, time.Now())
		s.domainLastAccess.Set(domain, time.Now())
		
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
		
		// Log each found secret immediately in real-time
		for _, secret := range secrets {
			// This ensures real-time display of found secrets
			s.logger.SecretFound(secret.Type, secret.Value, url)
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
		
		// Only log a summary after logging individual secrets
		if len(secrets) > 0 {
			s.logger.Success("Worker %d: processed URL %s, found %d secrets", id, url, len(secrets))
		} else {
			s.logger.Debug("Worker %d: processed URL %s, found no secrets", id, url)
		}
	}
}

// handleRequestError handles errors during content fetching
func (s *Scheduler) handleRequestError(err error, domain, url string) bool {
	// Check if error is caused by timeout
	if utils.IsTimeoutError(err) {
		s.logger.Warning("Request to %s timed out, marking as failed", url)
		s.incrementFailedURLs()
		return true
	}

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
	
	// Domain-aware requeuing - add to the end but try to avoid clustering same domains
	// If the queue is longer than 20 items, insert at a more appropriate position
	if len(s.waitingURLs) > 20 {
		domain, err := utils.ExtractDomain(url)
		if err == nil {
			// Try to find a position where this domain doesn't have neighbors
			bestPosition := len(s.waitingURLs) // Default to end
			bestScore := 0
			
			// Score positions based on domain distance
			for i := 0; i < len(s.waitingURLs); i++ {
				score := 0
				
				// Check nearby positions, prioritizing gaps between different domains
				for j := -3; j <= 3; j++ {
					if i+j >= 0 && i+j < len(s.waitingURLs) {
						neighborDomain, err := utils.ExtractDomain(s.waitingURLs[i+j])
						if err == nil && neighborDomain != domain {
							score += 1
						}
					}
				}
				
				if score > bestScore {
					bestScore = score
					bestPosition = i
				}
			}
			
			// Insert at the best position if we found a good spot
			if bestScore > 0 && bestPosition < len(s.waitingURLs) {
				// Insert the URL at the best position
				s.waitingURLs = append(s.waitingURLs[:bestPosition], append([]string{url}, s.waitingURLs[bestPosition:]...)...)
				return
			}
		}
	}
	
	// Fallback to simply adding to the end
	s.waitingURLs = append(s.waitingURLs, url)
}

// hasAlternativeURL checks if there are URLs from different domains in the queue
func (s *Scheduler) hasAlternativeURL(currentDomain string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Check first 30 URLs in the queue to avoid excessive scanning
	checkLimit := 30
	if len(s.waitingURLs) < checkLimit {
		checkLimit = len(s.waitingURLs)
	}
	
	// Count different domains in the queue
	uniqueDomains := make(map[string]bool)
	
	for i := 0; i < checkLimit; i++ {
		if i >= len(s.waitingURLs) {
			break
		}
		
		domain, err := utils.ExtractDomain(s.waitingURLs[i])
		if err == nil {
			uniqueDomains[domain] = true
		}
	}
	
	// If we have at least 3 different domains including current one
	if len(uniqueDomains) >= 3 {
		// Check if we have a different domain in the first few URLs
		for i := 0; i < min(10, checkLimit); i++ {
			if i >= len(s.waitingURLs) {
				break
			}
			
			domain, err := utils.ExtractDomain(s.waitingURLs[i])
			if err == nil && domain != currentDomain {
				return true
			}
		}
	}
	
	// If we have only 1-2 domains total, we are less strict about alternatives
	if len(uniqueDomains) <= 2 {
		return false
	}
	
	// Otherwise require at least one different domain
	for domain := range uniqueDomains {
		if domain != currentDomain {
			return true
		}
	}
	
	return false
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

// printDomainStatistics prints domain-specific statistics
func (s *Scheduler) printDomainStatistics() {
	// Get domain statistics from domain manager
	domainStats := s.domainManager.GetDomainStatus()
	
	// Get blocking information
	blockedDomains := s.domainManager.GetBlockedDomains()
	
	s.logger.Info("Domain Statistics:")
	
	// Sort domains by URL count for consistent output
	domains := make([]string, 0, len(domainStats))
	for domain := range domainStats {
		domains = append(domains, domain)
	}
	
	utils.SortByValueDesc(domains, func(domain string) int {
		return domainStats[domain].TotalURLs
	})
	
	for _, domain := range domains {
		stats := domainStats[domain]
		
		// Check if domain is currently blocked
		blockStatus := ""
		if expiry, blocked := blockedDomains[domain]; blocked {
			remaining := time.Until(expiry).Round(time.Second)
			blockStatus = fmt.Sprintf(" [BLOCKED for %s]", remaining)
		}
		
		s.logger.Info("  - %s: %d URLs, %d processed, %d failed%s", 
			domain, stats.TotalURLs, stats.ProcessedURLs, stats.FailedURLs, blockStatus)
	}
	
	// Show retry information
	s.logger.Info("Domain Retry Counts:")
	
	retryDomains := make([]string, 0, len(s.stats.DomainRetries))
	for domain := range s.stats.DomainRetries {
		retryDomains = append(retryDomains, domain)
	}
	
	utils.SortByValueDesc(retryDomains, func(domain string) int {
		return s.stats.DomainRetries[domain]
	})
	
	for _, domain := range retryDomains {
		count := s.stats.DomainRetries[domain]
		if count > 0 {
			s.logger.Info("  - %s: retried %d times", domain, count)
		}
	}
}
