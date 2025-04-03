package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type CacheService struct {
	cache map[string][]Secret
	mu    sync.RWMutex
}

func NewCacheService() *CacheService {
	return &CacheService{
		cache: make(map[string][]Secret),
	}
}

/* 
   Generates a deterministic hash-based cache key for the given content
*/
func (c *CacheService) GetCacheKey(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (c *CacheService) GetSecrets(content string) ([]Secret, bool) {
	key := c.GetCacheKey(content)
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	secrets, found := c.cache[key]
	return secrets, found
}

func (c *CacheService) StoreSecrets(content string, secrets []Secret) {
	key := c.GetCacheKey(content)
	
	sortedSecrets := make([]Secret, len(secrets))
	copy(sortedSecrets, secrets)
	
	sort.Slice(sortedSecrets, func(i, j int) bool {
		if sortedSecrets[i].Type != sortedSecrets[j].Type {
			return sortedSecrets[i].Type < sortedSecrets[j].Type
		}
		return sortedSecrets[i].Value < sortedSecrets[j].Value
	})
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = sortedSecrets
}

func (c *CacheService) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache = make(map[string][]Secret)
}

/* 
   Returns a deduplicated list of secrets in deterministic order
*/
func (c *CacheService) GetUniqueSecrets(secrets []Secret) []Secret {
	uniqueMap := make(map[string]Secret)
	
	for _, secret := range secrets {
		key := fmt.Sprintf("%s:%s", secret.Type, secret.Value)
		uniqueMap[key] = secret
	}
	
	result := make([]Secret, 0, len(uniqueMap))
	keys := make([]string, 0, len(uniqueMap))
	
	for k := range uniqueMap {
		keys = append(keys, k)
	}
	
	sort.Strings(keys)
	
	for _, k := range keys {
		result = append(result, uniqueMap[k])
	}
	
	return result
}

/* 
   Creates a consistent composite key for a secret based on its attributes
*/
func (c *CacheService) GetStableSecretKey(secretType, secretValue, url string) string {
	return strings.Join([]string{url, secretType, secretValue}, ":")
}
