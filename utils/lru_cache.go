package utils

import (
	"container/list"
	"sync"
	"time"
)

// LRUCache implements a thread-safe Least Recently Used (LRU) cache
type LRUCache struct {
	capacity int
	items    map[string]*list.Element
	list     *list.List
	mu       sync.Mutex
}

// cacheItem represents an item in the LRU cache
type cacheItem struct {
	key   string
	value interface{}
}

// NewLRUCache creates a new LRU cache with the specified capacity
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

// Get gets a value from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element) // Mark as recently used
		return element.Value.(*cacheItem).value, true
	}
	
	return nil, false
}

// Put puts a value in the cache
func (c *LRUCache) Put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// If key already exists, update it and move to front
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		element.Value.(*cacheItem).value = value
		return
	}
	
	// Add new item to front of list
	element := c.list.PushFront(&cacheItem{
		key:   key,
		value: value,
	})
	c.items[key] = element
	
	// If over capacity, remove least recently used item
	if c.list.Len() > c.capacity {
		c.removeLRU()
	}
}

// Contains checks if a key exists in the cache
func (c *LRUCache) Contains(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	_, found := c.items[key]
	return found
}

// Remove removes a key from the cache
func (c *LRUCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		c.list.Remove(element)
		delete(c.items, key)
	}
}

// Clear clears the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.items = make(map[string]*list.Element)
	c.list.Init()
}

// Size returns the number of items in the cache
func (c *LRUCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	return c.list.Len()
}

// Keys returns all keys in the cache
func (c *LRUCache) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	
	return keys
}

// removeLRU removes the least recently used item from the cache
func (c *LRUCache) removeLRU() {
	if element := c.list.Back(); element != nil {
		item := element.Value.(*cacheItem)
		delete(c.items, item.key)
		c.list.Remove(element)
	}
}

// GetWithExpiry gets a value from the cache and checks if it's expired
func (c *LRUCache) GetWithExpiry(key string, maxAge time.Duration) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		item := element.Value.(*cacheItem)
		if timestamp, ok := item.value.(time.Time); ok {
			if time.Since(timestamp) < maxAge {
				c.list.MoveToFront(element) // Mark as recently used
				return item.value, true
			} else {
				// Remove expired item
				c.list.Remove(element)
				delete(c.items, key)
				return nil, false
			}
		}
		c.list.MoveToFront(element) // Mark as recently used
		return item.value, true
	}
	
	return nil, false
}
