package networking

import (
	"sync"
	"time"

	"github.com/secrethound/utils"
)

// DomainManager groups URLs by domain and manages blocked domains
type DomainManager struct {
	domains        map[string][]string
	blockedDomains map[string]time.Time
	domainStats    map[string]*DomainStats
	mu             sync.RWMutex
}

// DomainStats tracks statistics for a domain
type DomainStats struct {
	TotalURLs         int
	ProcessedURLs     int
	FailedURLs        int
	SuccessfulURLs    int
	LastAccessTime    time.Time
	AverageResponseTime time.Duration
	TotalBlocks       int
}

// NewDomainManager creates a new domain manager
func NewDomainManager() *DomainManager {
	return &DomainManager{
		domains:        make(map[string][]string),
		blockedDomains: make(map[string]time.Time),
		domainStats:    make(map[string]*DomainStats),
	}
}

// GroupURLsByDomain groups URLs by their domain
func (dm *DomainManager) GroupURLsByDomain(urls []string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	// Clear existing data
	dm.domains = make(map[string][]string)
	
	for _, url := range urls {
		domain, err := utils.ExtractDomain(url)
		if err != nil {
			// Skip URLs with invalid domain
			continue
		}
		
		// Add URL to its domain group
		dm.domains[domain] = append(dm.domains[domain], url)
		
		// Initialize or update domain stats
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

// AddBlockedDomain adds a domain to the blocked list
func (dm *DomainManager) AddBlockedDomain(domain string, duration time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	dm.blockedDomains[domain] = time.Now().Add(duration)
	
	// Update domain stats
	if _, exists := dm.domainStats[domain]; exists {
		dm.domainStats[domain].TotalBlocks++
	}
}

// IsBlocked checks if a domain is currently blocked
func (dm *DomainManager) IsBlocked(domain string) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	expiry, exists := dm.blockedDomains[domain]
	if !exists {
		return false
	}
	
	// If expiry time has passed, unblock the domain
	if time.Now().After(expiry) {
		// We can't modify the map here due to the RLock
		// But we'll return false and the next call to IsBlocked
		// will again check the expiry time
		return false
	}
	
	return true
}

// GetNextDomain gets the next available domain
func (dm *DomainManager) GetNextDomain() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	var candidateDomains []string
	
	// Find all unblocked domains
	for domain := range dm.domains {
		if !dm.isBlockedNoLock(domain) && len(dm.domains[domain]) > 0 {
			candidateDomains = append(candidateDomains, domain)
		}
	}
	
	if len(candidateDomains) == 0 {
		return ""
	}
	
	// For simplicity, return the first unblocked domain
	// In a more advanced implementation, we could prioritize based on:
	// - Domains with more URLs remaining
	// - Domains that haven't been accessed recently (to spread load)
	// - Domains with higher success rates
	return candidateDomains[0]
}

// isBlockedNoLock is the same as IsBlocked but doesn't acquire a lock
// It should only be called when the lock is already held
func (dm *DomainManager) isBlockedNoLock(domain string) bool {
	expiry, exists := dm.blockedDomains[domain]
	if !exists {
		return false
	}
	
	// If expiry time has passed, unblock the domain
	if time.Now().After(expiry) {
		delete(dm.blockedDomains, domain)
		return false
	}
	
	return true
}

// GetURLsForDomain gets the URLs for a specific domain
func (dm *DomainManager) GetURLsForDomain(domain string) []string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	return dm.domains[domain]
}

// RemoveURL removes a URL from its domain group
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
			// Remove URL from slice
			dm.domains[domain] = append(urls[:i], urls[i+1:]...)
			break
		}
	}
}

// RecordURLProcessed records that a URL has been processed
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
		
		// Update average response time
		if stats.AverageResponseTime == 0 {
			stats.AverageResponseTime = responseTime
		} else {
			// Weighted average, giving more weight to recent response times
			stats.AverageResponseTime = (stats.AverageResponseTime*3 + responseTime) / 4
		}
	} else {
		stats.FailedURLs++
	}
}

// GetDomainCount returns the number of domains
func (dm *DomainManager) GetDomainCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	return len(dm.domains)
}

// GetURLCount returns the total number of URLs
func (dm *DomainManager) GetURLCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	total := 0
	for _, urls := range dm.domains {
		total += len(urls)
	}
	
	return total
}

// GetBlockedDomainCount returns the number of blocked domains
func (dm *DomainManager) GetBlockedDomainCount() int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	count := 0
	for domain := range dm.blockedDomains {
		if dm.isBlockedNoLock(domain) {
			count++
		}
	}
	
	return count
}

// GetBlockedDomains returns a list of blocked domains
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

// GetDomainStatus returns a summary of all domain statuses
func (dm *DomainManager) GetDomainStatus() map[string]DomainStats {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	status := make(map[string]DomainStats)
	for domain, stats := range dm.domainStats {
		status[domain] = *stats
	}
	
	return status
}

// GetDomainStructure returns the domain-based URL structure
func (dm *DomainManager) GetDomainStructure() map[string]int {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	structure := make(map[string]int)
	for domain, urls := range dm.domains {
		structure[domain] = len(urls)
	}
	
	return structure
}
