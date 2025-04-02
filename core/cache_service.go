package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// CacheService provides deterministic caching for secret detection results
type CacheService struct {
	cache map[string][]Secret
	mu    sync.RWMutex
}

// NewCacheService creates a new cache service instance
func NewCacheService() *CacheService {
	return &CacheService{
		cache: make(map[string][]Secret),
	}
}

// GetCacheKey generates a deterministic cache key for content
func (c *CacheService) GetCacheKey(content string) string {
	// Generate a hash of the content
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// GetSecrets retrieves cached secrets for content if available
func (c *CacheService) GetSecrets(content string) ([]Secret, bool) {
	key := c.GetCacheKey(content)
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	secrets, found := c.cache[key]
	return secrets, found
}

// StoreSecrets stores secrets for content in the cache
func (c *CacheService) StoreSecrets(content string, secrets []Secret) {
	key := c.GetCacheKey(content)
	
	// Sort secrets deterministically to ensure consistent order
	sortedSecrets := make([]Secret, len(secrets))
	copy(sortedSecrets, secrets)
	
	sort.Slice(sortedSecrets, func(i, j int) bool {
		// Sort by type, then value
		if sortedSecrets[i].Type != sortedSecrets[j].Type {
			return sortedSecrets[i].Type < sortedSecrets[j].Type
		}
		return sortedSecrets[i].Value < sortedSecrets[j].Value
	})
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = sortedSecrets
}

// Clear empties the cache
func (c *CacheService) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache = make(map[string][]Secret)
}

// GetUniqueSecrets removes any duplicates from a slice of secrets
func (c *CacheService) GetUniqueSecrets(secrets []Secret) []Secret {
	uniqueMap := make(map[string]Secret)
	
	for _, secret := range secrets {
		// Create a unique key combining type and value
		key := fmt.Sprintf("%s:%s", secret.Type, secret.Value)
		uniqueMap[key] = secret
	}
	
	// Convert back to slice in a deterministic order
	result := make([]Secret, 0, len(uniqueMap))
	keys := make([]string, 0, len(uniqueMap))
	
	for k := range uniqueMap {
		keys = append(keys, k)
	}
	
	// Sort keys for deterministic order
	sort.Strings(keys)
	
	for _, k := range keys {
		result = append(result, uniqueMap[k])
	}
	
	return result
}

// GetStableSecretKey generates a consistent key for a secret
func (c *CacheService) GetStableSecretKey(secretType, secretValue, url string) string {
	return strings.Join([]string{url, secretType, secretValue}, ":")
}
