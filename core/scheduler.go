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
	
	recentDomains := utils.NewLRUCache(5)
	
	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("Worker %d stopping due to cancellation", id)
			return
		default:
		}
		
		url, ok := s.GetNextURL()
		if (!ok) {
			s.logger.Debug("Worker %d stopping: no more URLs to process", id)
			return
		}
		
		domain, err := utils.ExtractDomain(url)
		if err != nil {
			s.logger.Warning("Worker %d: failed to extract domain from URL %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		if s.domainManager.IsBlocked(domain) {
			s.logger.Debug("Worker %d: domain %s is blocked, requeueing URL %s", id, domain, url)
			s.requeueURL(url)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		lastAccess, found := s.domainLastAccess.Get(domain)
		if found && time.Since(lastAccess) < s.domainCooldown {
			if s.hasAlternativeURL(domain) {
				time.Sleep(10 * time.Millisecond)
				
				if len(s.domainManager.GetDomainList()) <= 3 {
					wait := s.domainCooldown - time.Since(lastAccess)
					if wait > 0 {
						time.Sleep(wait / 2)
					}
				} else {
					s.requeueURL(url)
					continue
				}
			} else {
				wait := s.domainCooldown - time.Since(lastAccess)
				if wait > 0 {
					time.Sleep(wait)
				}
			}
		}
		
		if recentDomains.Contains(domain) {
			if s.shouldRequeueDomainURL(domain, id) {
				s.logger.Debug("Worker %d: recently accessed domain %s, requeueing URL %s", id, domain, url)
				s.requeueURL(url)
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		
		recentDomains.Put(domain, time.Now())
		s.domainLastAccess.Set(domain, time.Now())
		
		s.logger.Debug("Worker %d: processing URL %s", id, url)
		content, err := s.client.GetJSContent(url)
		
		if err != nil {
			if s.handleRequestError(err, domain, url) {
				continue
			}
			
			s.logger.Error("Worker %d: failed to fetch content from %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		secrets, err := s.processor.ProcessJSContent(content, url)
		if err != nil {
			s.logger.Error("Worker %d: failed to process content from %s: %v", id, url, err)
			s.incrementFailedURLs()
			continue
		}
		
		for _, secret := range secrets {
			s.logger.SecretFound(secret.Type, secret.Value, url)
		}
		
		if s.writer != nil && len(secrets) > 0 {
			for _, secret := range secrets {
				err := s.writer.WriteSecret(secret.Type, secret.Value, secret.URL, secret.Context, secret.Line)
				if err != nil {
					s.logger.Error("Worker %d: failed to write secret to output file: %v", id, err)
				}
			}
		}
		
		s.mutex.Lock()
		s.stats.ProcessedURLs++
		s.stats.TotalSecrets += len(secrets)
		s.mutex.Unlock()
		
		if len(secrets) > 0 {
			s.logger.Debug("Worker %d: processed URL %s, found %d secrets", id, url, len(secrets))
		} else {
			s.logger.Debug("Worker %d: processed URL %s, found no secrets", id, url)
		}
	}
}

/* 
	Handles different types of request errors (timeout, rate limit, WAF, temporary)
	and determines appropriate actions like requeuing or blocking domains
*/
func (s *Scheduler) handleRequestError(err error, domain, url string) bool {
	if utils.IsTimeoutError(err) {
		s.logger.Warning("Request to %s timed out, marking as failed", url)
		s.incrementFailedURLs()
		return true
	}

	if utils.IsRateLimitError(err) {
		s.mutex.Lock()
		s.stats.RateLimitHits++
		s.mutex.Unlock()
		
		s.logger.Warning("Domain %s is being rate limited, adding to blocked list", domain)
		
		blockDuration := time.Duration(2+s.getDomainRetryCount(domain)) * time.Minute
		s.domainManager.AddBlockedDomain(domain, blockDuration)
		s.incrementDomainRetry(domain)
		
		s.requeueURL(url)
		return true
	}
	
	if utils.IsWAFError(err) {
		s.mutex.Lock()
		s.stats.WAFBlockHits++
		s.mutex.Unlock()
		
		s.logger.Warning("Domain %s is blocking with WAF, adding to blocked list", domain)
		
		blockDuration := time.Duration(5+s.getDomainRetryCount(domain)*2) * time.Minute
		s.domainManager.AddBlockedDomain(domain, blockDuration)
		s.incrementDomainRetry(domain)
		
		s.requeueURL(url)
		return true
	}
	
	if utils.IsTemporaryError(err) {
		s.logger.Debug("Temporary error for domain %s, will retry URL %s", domain, url)
		s.requeueURL(url)
		return true
	}
	
	return false
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
