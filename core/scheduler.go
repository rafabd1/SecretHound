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
	noProgress    bool
	silent        bool
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
	processor *Processor, writer *output.Writer, logger *output.Logger, concurrency int, noProgress bool, silent bool) (*Scheduler, error) {
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scheduler{
		domainManager: domainManager,
		client:        client,
		processor:     processor,
		writer:        writer,
		logger:        logger,
		concurrency:   concurrency,
		noProgress:    noProgress,
		silent:        silent,
		ctx:           ctx,
		cancel:        cancel,
		stats: SchedulerStats{
			DomainRetries: make(map[string]int),
			StartTime:     time.Now(),
		},
	}, nil
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

	var progressBar *output.ProgressBar
	if !s.noProgress && !s.silent {
		progressBar = output.NewProgressBar(len(urls), 40)
		progressBar.SetPrefix("Processing URLs: ")
	s.logger.SetProgressBar(progressBar)
		progressBar.Start()
		progressBar.SetSuffix("Secrets: 0 | Rate: 0.0/s")
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	done := make(chan struct{})

	if progressBar != nil {
	go func() {
		for {
			select {
			case <-ticker.C:
				s.mutex.Lock()
				processedCount := s.stats.ProcessedURLs
					failedCount := s.stats.FailedURLs
				secretsFound := s.stats.TotalSecrets
					startTime := s.stats.StartTime
				s.mutex.Unlock()

					totalCompleted := processedCount + failedCount
					progressBar.Update(totalCompleted)

					elapsedSeconds := time.Since(startTime).Seconds()
					rate := 0.0
					if elapsedSeconds > 0 {
						rate = float64(totalCompleted) / elapsedSeconds
					}
				progressBar.SetSuffix(fmt.Sprintf("Secrets: %d | Rate: %.1f/s",
					secretsFound,
						rate))
				case <-done:
					return
				}
			}
		}()
	}

	go func() {
		completionTicker := time.NewTicker(100 * time.Millisecond)
		defer completionTicker.Stop()
		
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-completionTicker.C:
				s.mutex.Lock()
				totalCompleted := s.stats.ProcessedURLs + s.stats.FailedURLs
				totalExpected := s.stats.TotalURLs
				s.mutex.Unlock()

				if totalCompleted >= totalExpected {
					s.logger.Debug("Completion monitor: All %d URLs accounted for (%d processed, %d failed). Canceling context.",
						totalExpected, s.stats.ProcessedURLs, s.stats.FailedURLs)
					s.cancel()
					return
				}
			}
		}
	}()

	s.workerPool = utils.NewWorkerPool(s.concurrency, len(urls))

	for i := 0; i < s.concurrency; i++ {
		s.waitGroup.Add(1)
		go s.worker(i)
	}

	s.waitGroup.Wait()

	s.cancel()

	if progressBar != nil {
		close(done)
	progressBar.Stop()
		progressBar.Finalize()
		s.logger.SetProgressBar(nil)
	}

	s.mutex.Lock()
	s.stats.EndTime = time.Now()
	duration := s.stats.EndTime.Sub(s.stats.StartTime)
	urlsPerSecond := 0.0
	if duration.Seconds() > 0 {
		urlsPerSecond = float64(s.stats.ProcessedURLs) / duration.Seconds()
	}
	processed := s.stats.ProcessedURLs
	secrets := s.stats.TotalSecrets
	failed := s.stats.FailedURLs
	rateLimitHits := s.stats.RateLimitHits
	wafHits := s.stats.WAFBlockHits
	s.mutex.Unlock()

	s.logger.Info("Processing completed in %.2f seconds", duration.Seconds())
	s.logger.Info("Processed %d URLs (%.2f URLs/second)", processed, urlsPerSecond)
	s.logger.Info("Found %d secrets", secrets)
	s.logger.Info("Failed to process %d URLs", failed)
	s.logger.Info("Encountered rate limiting %d times", rateLimitHits)
	s.logger.Info("Encountered WAF blocks %d times", wafHits)

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

func (s *Scheduler) worker(id int) {
	defer s.waitGroup.Done()
	s.logger.Debug("Worker %d started", id)
	
	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("Worker %d stopping due to context cancellation", id)
			return
		default:
			url, hasMore := s.GetNextURL()
		
			if !hasMore {
				s.logger.Debug("Worker %d: Queue empty and context likely canceled. Exiting.", id)
			return
		}
		
			if url == "" {
				s.logger.Debug("Worker %d: Queue temporarily empty, sleeping.", id)
				time.Sleep(time.Duration(150+utils.RandomInt(0, 100)) * time.Millisecond)
			continue
		}
		
			domain, err := utils.ExtractDomain(url)
			if err != nil {
				s.logger.Warning("Worker %d: failed to extract domain from %s: %v", id, url, err)
				s.incrementFailedURLs(domain)
			continue
		}
		
			s.logger.Debug("Worker %d: Requesting URL %s", id, url)
			startTime := time.Now()

			content, fetchErr := s.client.GetJSContent(url)
			requestDuration := time.Since(startTime)

			if fetchErr != nil {
				s.logger.Warning("Worker %d: Failed to fetch %s after retries: %v", id, url, fetchErr)
				s.incrementFailedURLs(domain)
				continue
			}

			s.logger.Debug("Worker %d: Processing content from %s (Fetch took %v)", id, url, requestDuration)
			processStartTime := time.Now()
			secrets, processErr := s.processor.ProcessJSContent(content, url)
			processingDuration := time.Since(processStartTime)
			totalDuration := time.Since(startTime)
		
			if processErr != nil {
				s.logger.Warning("Worker %d: Failed to process content from %s: %v", id, url, processErr)
				s.incrementFailedURLs(domain)
				continue
			}
			
			s.incrementProcessedURLs(domain, totalDuration)

			if len(secrets) > 0 {
				s.mutex.Lock()
				s.stats.TotalSecrets += len(secrets)
				s.mutex.Unlock()
				s.logger.Debug("Worker %d found %d secrets in %s (Process took %v)", id, len(secrets), url, processingDuration)
		for _, secret := range secrets {
			s.logger.SecretFound(secret.Type, secret.Value, url)
					if s.writer != nil {
						writeErr := s.writer.WriteSecret(url, secret.Type, secret.Value, url, secret.Context, "", secret.Line)
						if writeErr != nil {
							s.logger.Error("Worker %d: failed to write secret to output file: %v", id, writeErr)
				}
			}
		}
			} else {
				s.logger.Debug("Worker %d found 0 secrets in %s (Process took %v)", id, url, processingDuration)
			}
		}
	}
}

func (s *Scheduler) incrementFailedURLs(domain string) {
	s.mutex.Lock()
	s.stats.FailedURLs++
	s.mutex.Unlock()
	s.domainManager.RecordURLProcessed(domain, false, 0)
}

func (s *Scheduler) incrementProcessedURLs(domain string, duration time.Duration) {
	s.mutex.Lock()
	s.stats.ProcessedURLs++
	s.mutex.Unlock()
	s.domainManager.RecordURLProcessed(domain, true, duration)
}

func (s *Scheduler) GetNextURL() (string, bool) {
	s.mutex.Lock()
	
	if len(s.waitingURLs) > 0 {
	url := s.waitingURLs[0]
	s.waitingURLs = s.waitingURLs[1:]
		s.mutex.Unlock()
	return url, true
}

	select {
	case <-s.ctx.Done():
		s.mutex.Unlock()
		return "", false
	default:
		s.mutex.Unlock()
		return "", true
	}
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
