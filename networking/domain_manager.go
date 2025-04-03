package networking

import (
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/utils"
)

type DomainManager struct {
	domains        map[string][]string
	blockedDomains map[string]time.Time
	domainStats    map[string]*DomainStats
	mu             sync.RWMutex
}

type DomainStats struct {
	TotalURLs           int
	ProcessedURLs       int
	FailedURLs          int
	SuccessfulURLs      int
	LastAccessTime      time.Time
	AverageResponseTime time.Duration
	TotalBlocks         int
}

func NewDomainManager() *DomainManager {
	return &DomainManager{
		domains:        make(map[string][]string),
		blockedDomains: make(map[string]time.Time),
		domainStats:    make(map[string]*DomainStats),
	}
}

func (dm *DomainManager) GroupURLsByDomain(urls []string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	dm.domains = make(map[string][]string)
	
	for _, url := range urls {
		domain, err := utils.ExtractDomain(url)
		if err != nil {
			continue
		}
		
		dm.domains[domain] = append(dm.domains[domain], url)
		
		if _, exists := dm.domainStats[domain]; !exists {
			dm.domainStats[domain] = &DomainStats{
				TotalURLs:      0,
				ProcessedURLs:  0,
				FailedURLs:     0,
				SuccessfulURLs: 0,
				LastAccessTime: time.Time{},
			}
		}
		
		dm.domainStats[domain].TotalURLs++
	}
}

func (dm *DomainManager) AddBlockedDomain(domain string, duration time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	dm.blockedDomains[domain] = time.Now().Add(duration)
	
	if _, exists := dm.domainStats[domain]; exists {
		dm.domainStats[domain].TotalBlocks++
	}
}

func (dm *DomainManager) IsBlocked(domain string) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	expiry, exists := dm.blockedDomains[domain]
	if !exists {
		return false
	}
	
	if time.Now().After(expiry) {
		return false
	}
	
	return true
}

/* 
   Returns the next available domain that is not blocked and has URLs to process
*/
func (dm *DomainManager) GetNextDomain() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	var candidateDomains []string
	
	for domain := range dm.domains {
		if !dm.isBlockedNoLock(domain) && len(dm.domains[domain]) > 0 {
			candidateDomains = append(candidateDomains, domain)
		}
	}
	
	if len(candidateDomains) == 0 {
		return ""
	}
	
	return candidateDomains[0]
}

func (dm *DomainManager) isBlockedNoLock(domain string) bool {
	expiry, exists := dm.blockedDomains[domain]
	if !exists {
		return false
	}
	
	if time.Now().After(expiry) {
		delete(dm.blockedDomains, domain)
		return false
	}
	
	return true
}

func (dm *DomainManager) GetURLsForDomain(domain string) []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	urls := make([]string, len(dm.domains[domain]))
	copy(urls, dm.domains[domain])
	
	return urls
}

func (dm *DomainManager) RemoveURL(url string) {
	domain, err := utils.ExtractDomain(url)
	if err != nil {
		return
	}
	
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	urls := dm.domains[domain]
	for i, u := range urls {
		if u == url {
			dm.domains[domain] = append(urls[:i], urls[i+1:]...)
			break
		}
	}
}

func (dm *DomainManager) RecordURLProcessed(url string, success bool, responseTime time.Duration) {
	domain, err := utils.ExtractDomain(url)
	if err != nil {
		return
	}
	
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	stats, exists := dm.domainStats[domain]
	if !exists {
		return
	}
	
	stats.ProcessedURLs++
	stats.LastAccessTime = time.Now()
	
	if success {
		stats.SuccessfulURLs++
		
		if stats.AverageResponseTime == 0 {
			stats.AverageResponseTime = responseTime
		} else {
			stats.AverageResponseTime = (stats.AverageResponseTime*3 + responseTime) / 4
		}
	} else {
		stats.FailedURLs++
	}
}

func (dm *DomainManager) GetDomainCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	return len(dm.domains)
}

func (dm *DomainManager) GetURLCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	total := 0
	for _, urls := range dm.domains {
		total += len(urls)
	}
	
	return total
}

func (dm *DomainManager) GetBlockedDomainCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	count := 0
	for domain := range dm.blockedDomains {
		if dm.isBlockedNoLock(domain) {
			count++		}
	}
	
	return count
}

func (dm *DomainManager) GetBlockedDomains() map[string]time.Time {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	blockedDomains := make(map[string]time.Time)
	for domain, expiry := range dm.blockedDomains {
		if time.Now().Before(expiry) {
			blockedDomains[domain] = expiry
		}
	}
	
	return blockedDomains
}

func (dm *DomainManager) GetDomainStatus() map[string]DomainStats {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	status := make(map[string]DomainStats)
	for domain, stats := range dm.domainStats {
		status[domain] = *stats
	}
	
	return status
}

func (dm *DomainManager) GetDomainStructure() map[string]int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	structure := make(map[string]int)
	for domain, urls := range dm.domains {
		structure[domain] = len(urls)
	}
	
	return structure
}

func (dm *DomainManager) GetDomainList() []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	domains := make([]string, 0, len(dm.domains))
	for domain := range dm.domains {
		domains = append(domains, domain)
	}
	
	return domains
}

func (dm *DomainManager) GetUnblockedDomains() []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	domains := make([]string, 0, len(dm.domains))
	for domain := range dm.domains {
		if !dm.isBlockedNoLock(domain) {
			domains = append(domains, domain)
		}
	}
	
	return domains
}
