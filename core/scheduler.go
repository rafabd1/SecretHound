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

func NewScheduler(domainManager *networking.DomainManager, client *networking.Client, 
	processor *Processor, writer *output.Writer, logger *output.Logger) *Scheduler {
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scheduler{
		domainManager: domainManager,
		client:        client,
		processor:     processor,
		writer:        writer,
		logger:        logger,
		concurrency:   10,
		ctx:           ctx,
		cancel:        cancel,
		domainLastAccess: utils.NewSafeMap[string, time.Time](),
		domainCooldown: 500 * time.Millisecond,
		stats: SchedulerStats{
			DomainRetries: make(map[string]int),
			StartTime:     time.Now(),
		},
	}
}

func (s *Scheduler) Schedule(urls []string) error {
	s.mutex.Lock()
	s.stats.TotalURLs = len(urls)
	s.stats.StartTime = time.Now()
	s.mutex.Unlock()

	s.domainManager.GroupURLsByDomain(urls)
	domains := s.domainManager.GetDomainList()
	
	s.buildBalancedWorkQueue(domains)

	time.Sleep(200 * time.Millisecond)

	progressBar := output.NewProgressBar(len(urls), 40)
	progressBar.SetPrefix("Processing: ")

	s.logger.SetProgressBar(progressBar)

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

				progressBar.Update(processedCount)

				progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s",
					secretsFound,
					float64(processedCount)/time.Since(s.stats.StartTime).Seconds()))
			case <-s.ctx.Done():
				return
			}
		}
	}()
	
	progressBar.Start()

	s.workerPool = utils.NewWorkerPool(s.concurrency, len(urls))

	for i := 0; i < s.concurrency; i++ {
		s.waitGroup.Add(1)
		go s.worker(i)
	}

	s.waitGroup.Wait()

	progressBar.Stop()

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

	if s.logger.IsVerbose() {
		s.printDomainStatistics()
	}

	return nil
}

/* 
	Builds a balanced queue of URLs by taking one URL from each domain in rounds
	to ensure fair distribution across domains
*/
func (s *Scheduler) buildBalancedWorkQueue(domains []string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.waitingURLs = make([]string, 0)
	
	roundRobinCount := 0
	continueFetching := true
	
	utils.SimpleSortByDomainCount(domains, func(domain string) int {
		return len(s.domainManager.GetURLsForDomain(domain))
	})
	
	for continueFetching {
		continueFetching = false
		
		for _, domain := range domains {
			urls := s.domainManager.GetURLsForDomain(domain)
			
			if roundRobinCount < len(urls) {
				s.waitingURLs = append(s.waitingURLs, urls[roundRobinCount])
				continueFetching = true
			}
		}
		
		roundRobinCount++
	}
	
	s.shuffleWithDomainAwareness(s.waitingURLs)
	
	s.logger.Debug("Built balanced work queue with %d URLs", len(s.waitingURLs))
}

/* 
	Shuffles the URLs while maintaining distance between URLs from the same domain
	to prevent hammering a single domain with consecutive requests
*/
func (s *Scheduler) shuffleWithDomainAwareness(urls []string) {
	if len(urls) <= 1 {
		return
	}
	
	domainIndices := make(map[string][]int)
	
	for i, url := range urls {
		domain, err := utils.ExtractDomain(url)
		if err != nil {
			continue
		}
		
		domainIndices[domain] = append(domainIndices[domain], i)
	}
	
	if len(domainIndices) > 1 {
		domains := make([]string, 0, len(domainIndices))
		for domain := range domainIndices {
			domains = append(domains, domain)
		}
		
		utils.SortByValueDesc(domains, func(domain string) int {
			return len(domainIndices[domain])
		})
		
		newURLs := make([]string, len(urls))
		position := 0
		
		for len(domains) > 0 {
			for i := 0; i < len(domains); i++ {
				domain := domains[i]
				indices := domainIndices[domain]
				
				if len(indices) == 0 {
					domains = append(domains[:i], domains[i+1:]...)
					i--
					continue
				}
				
				newURLs[position] = urls[indices[0]]
				position++
				
				domainIndices[domain] = indices[1:]
			}
		}
		
		copy(urls, newURLs)
	}
}

/* 
	Determines if a URL from a specific domain should be requeued based on domain
	status, pending request count, and domain diversity in the queue
*/
func (s *Scheduler) shouldRequeueDomainURL(domain string, worker int) bool {
	if (!s.hasAlternativeURL(domain)) {
		return false
	}
	
	domainPendingCount := s.countPendingURLsForDomain(domain)
	
	domainCount := s.domainManager.GetDomainCount()
	if (domainCount <= 3) {
		return false
	}
	
	if (domainPendingCount > 5) {
		return utils.RandomInt(0, 100) < 20
	}
	
	return utils.RandomInt(0, 100) < 60
}

func (s *Scheduler) countPendingURLsForDomain(targetDomain string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	count := 0
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

func (s *Scheduler) worker(id int) {
	defer s.waitGroup.Done()
	s.logger.Debug("Worker %d started", id)

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("Worker %d stopping due to context cancellation", id)
			return
		default:
			// Get next URL
			url, hasMore := s.GetNextURL()
			if !hasMore {
				// Check if there are still URLs being processed or waiting
				s.mutex.Lock()
				activeURLs := len(s.waitingURLs) > 0 // Check if queue still has items
				// Add check for active workers if workerPool provides such info, otherwise assume work might still be ongoing if queue emptied recently
				s.mutex.Unlock()

				if !activeURLs /* && s.workerPool.ActiveCount() == 1 */ { // Assuming workerPool has ActiveCount or similar
					s.logger.Debug("Worker %d found no more URLs and likely no active work, exiting.", id)
					return // No more URLs and other workers likely done too
				}
				// Still URLs potentially being processed by others or waiting for cooldown/unblock
				s.logger.Debug("Worker %d found no URL, sleeping briefly.", id)
				time.Sleep(500 * time.Millisecond) // Sleep briefly and try again
				continue
			}

			domain, err := utils.ExtractDomain(url)
			if err != nil {
				s.logger.Warning("Worker %d: failed to extract domain from %s: %v", id, url, err)
				s.incrementFailedURLs()
				continue // Skip this URL
			}

			// Check if domain is explicitly blocked by the DomainManager
			if s.domainManager.IsBlocked(domain) {
				s.logger.Debug("Worker %d: domain %s is currently blocked, requeueing URL %s", id, domain, url)
				s.requeueURL(url) // Put it back for later attempt

				// Brief sleep to avoid immediate tight loop on the same blocked domain check by this worker
				time.Sleep(100 * time.Millisecond) 
				continue // Try to get a different URL in the next iteration
			}

			// Check scheduler's internal cooldown for the domain
			lastAccess, ok := s.domainLastAccess.Get(domain)
			if ok && time.Since(lastAccess) < s.domainCooldown {
				s.logger.Debug("Worker %d: domain %s is on internal cooldown, requeueing URL %s", id, domain, url)
				s.requeueURL(url) // Requeue for later attempt
				time.Sleep(s.domainCooldown - time.Since(lastAccess)) // Wait for cooldown
				continue
			}

			s.domainLastAccess.Set(domain, time.Now())

			s.logger.Debug("Worker %d: processing URL %s", id, url)

			startTime := time.Now()
			content, err := s.client.GetJSContent(url)

			s.mutex.Lock()
			s.stats.ProcessedURLs++
			s.mutex.Unlock()

			if err != nil {
				s.logger.Debug("Worker %d: error fetching %s: %v", id, url, err)
				
				// Handle specific errors (RateLimit, WAF, Network) and requeue if appropriate
				blocked := s.handleRequestError(err, domain, url, id)
				s.domainManager.RecordURLProcessed(url, false, 0)
				if !blocked { 
					// If it wasn't a block error, record as failed
					s.incrementFailedURLs()
				}
				// No need to requeue here, handleRequestError already does if needed.

				continue // Move to the next URL
			}

			// Record success
			responseTime := time.Since(startTime)
			s.domainManager.RecordURLProcessed(url, true, responseTime)

			// Process content
			secrets, processErr := s.processor.ProcessJSContent(content, url)
			if processErr != nil {
				s.logger.Warning("Worker %d: error processing content from %s: %v", id, url, processErr)
				s.incrementFailedURLs()
				continue // Skip to next URL if processing fails
			}

			if len(secrets) > 0 {
				s.mutex.Lock()
				s.stats.TotalSecrets += len(secrets)
				s.mutex.Unlock()
				for _, secret := range secrets {
					s.writer.WriteSecret(secret.Type, secret.Value, secret.URL, secret.Context, secret.Line)
				}
			}
		}
	}
}

/* 
	Handles different types of request errors (timeout, rate limit, WAF, temporary)
	and determines appropriate actions like requeuing or blocking domains
*/
func (s *Scheduler) handleRequestError(err error, domain, url string, workerId int) bool {
	isBlockError := false

	if utils.IsRateLimitError(err) {
		s.logger.Warning("Worker %d: Rate limit detected for domain %s while fetching %s", workerId, domain, url)
		s.mutex.Lock()
		s.stats.RateLimitHits++
		s.mutex.Unlock()
		s.AddBlockedDomain(domain)
		isBlockError = true
	} else if utils.IsWAFError(err) {
		s.logger.Warning("Worker %d: WAF block detected for domain %s while fetching %s", workerId, domain, url)
		s.mutex.Lock()
		s.stats.WAFBlockHits++
		s.mutex.Unlock()
		s.AddBlockedDomain(domain)
		isBlockError = true
	} else if utils.IsNetworkError(err) {
		// Check for specific network conditions if needed, otherwise just log
		s.logger.Warning("Worker %d: Network error for %s: %v", workerId, url, err)
		// Decide if network errors should cause blocking - maybe not unless persistent
	} else {
		s.logger.Error("Worker %d: Unhandled error for %s: %v", workerId, url, err)
	}

	// Requeue only if it was a blocking error and should be retried
	if isBlockError && s.shouldRequeueDomainURL(domain, workerId) {
		s.requeueURL(url)
		s.logger.Debug("Worker %d: Requeueing URL %s due to block on domain %s", workerId, url, domain)
	} else if isBlockError {
		s.logger.Debug("Worker %d: Domain %s blocked, but not requeueing URL %s based on policy", workerId, domain, url)
	}
	
	return isBlockError // Return true if the error resulted in the domain being blocked
}

func (s *Scheduler) getDomainRetryCount(domain string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stats.DomainRetries[domain]
}

func (s *Scheduler) incrementDomainRetry(domain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.DomainRetries[domain]++
}

func (s *Scheduler) incrementFailedURLs() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.FailedURLs++
	s.stats.ProcessedURLs++
}

func (s *Scheduler) AddBlockedDomain(domain string) {
	s.logger.Debug("Adding domain to blocked list: %s", domain)
	s.domainManager.AddBlockedDomain(domain, 5*time.Minute)
}

func (s *Scheduler) GetNextURL() (string, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.waitingURLs) == 0 {
		// Double check if all domains are done or just blocked
		if s.domainManager.GetURLCount() > 0 && s.domainManager.GetUnblockedDomainsCount() == 0 {
			// URLs exist, but all domains are blocked
			s.logger.Debug("GetNextURL: No URLs in immediate queue, but remaining domains are blocked.")
			// Returning false forces the worker to sleep and wait for unblocking or context cancel
			return "", false 
		}
		// Really no more URLs
		s.logger.Debug("GetNextURL: Queue is empty and no pending domains found.")
		return "", false
	}

	url := s.waitingURLs[0]
	s.waitingURLs = s.waitingURLs[1:]

	return url, true
}

/* 
	Intelligently requeues a URL by finding a position in the queue that maximizes
	distance from other URLs with the same domain
*/
func (s *Scheduler) requeueURL(url string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if len(s.waitingURLs) > 20 {
		domain, err := utils.ExtractDomain(url)
		if err == nil {
			bestPosition := len(s.waitingURLs)
			bestScore := 0
			
			for i := 0; i < len(s.waitingURLs); i++ {
				score := 0
				
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
			
			if bestScore > 0 && bestPosition < len(s.waitingURLs) {
				s.waitingURLs = append(s.waitingURLs[:bestPosition], append([]string{url}, s.waitingURLs[bestPosition:]...)...)
				return
			}
		}
	}
	
	s.waitingURLs = append(s.waitingURLs, url)
}

/* 
	Checks if there are URLs from different domains in the queue to allow
	alternating between domains instead of processing the same domain consecutively
*/
func (s *Scheduler) hasAlternativeURL(currentDomain string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	checkLimit := 30
	if len(s.waitingURLs) < checkLimit {
		checkLimit = len(s.waitingURLs)
	}
	
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
	
	if len(uniqueDomains) >= 3 {
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
	
	if len(uniqueDomains) <= 2 {
		return false
	}
	
	for domain := range uniqueDomains {
		if domain != currentDomain {
			return true
		}
	}
	
	return false
}

func (s *Scheduler) GetStats() SchedulerStats {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
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
	
	for domain, count := range s.stats.DomainRetries {
		statsCopy.DomainRetries[domain] = count
	}
	
	return statsCopy
}

func (s *Scheduler) Stop() {
	s.logger.Info("Stopping scheduler")
	s.cancel()
}

func (s *Scheduler) SetConcurrency(concurrency int) {
	s.concurrency = concurrency
}

func (s *Scheduler) GetActiveWorkers() int {
	if s.workerPool != nil {
		return s.workerPool.ActiveJobs()
	}
	return 0
}

func (s *Scheduler) printDomainStatistics() {
	domainStats := s.domainManager.GetDomainStatus()
	
	blockedDomains := s.domainManager.GetBlockedDomains()
	
	s.logger.Info("Domain Statistics:")
	
	domains := make([]string, 0, len(domainStats))
	for domain := range domainStats {
		domains = append(domains, domain)
	}
	
	utils.SortByValueDesc(domains, func(domain string) int {
		return domainStats[domain].TotalURLs
	})
	
	for _, domain := range domains {
		stats := domainStats[domain]
		
		blockStatus := ""
		if expiry, blocked := blockedDomains[domain]; blocked {
			remaining := time.Until(expiry).Round(time.Second)
			blockStatus = fmt.Sprintf(" [BLOCKED for %s]", remaining)
		}
		
		s.logger.Info("  - %s: %d URLs, %d processed, %d failed%s", 
			domain, stats.TotalURLs, stats.ProcessedURLs, stats.FailedURLs, blockStatus)
	}
	
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
