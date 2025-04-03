package utils

import (
	"container/list"
	"sort"
	"sync"
)

type LRUCache struct {
	capacity int
	items    map[string]*list.Element
	list     *list.List
	mu       sync.Mutex
}

type cacheItem struct {
	key   string
	value interface{}
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		return element.Value.(*cacheItem).value, true
	}
	
	return nil, false
}

func (c *LRUCache) Put(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		element.Value.(*cacheItem).value = value
		return
	}
	
	element := c.list.PushFront(&cacheItem{
		key:   key,
		value: value,
	})
	c.items[key] = element
	
	if c.list.Len() > c.capacity {
		c.removeLRU()
	}
}

func (c *LRUCache) Contains(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	_, found := c.items[key]
	return found
}

func (c *LRUCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		c.list.Remove(element)
		delete(c.items, key)
	}
}

func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.items = make(map[string]*list.Element)
	c.list.Init()
}

func (c *LRUCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	return c.list.Len()
}

func (c *LRUCache) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	
	return keys
}

func (c *LRUCache) removeLRU() {
	if element := c.list.Back(); element != nil {
		item := element.Value.(*cacheItem)
		delete(c.items, item.key)
		c.list.Remove(element)
	}
}

/* 
   Retrieves a value from the cache and checks if it has expired based on maxAge
*/
func (c *LRUCache) GetWithExpiry(key string, maxAge Duration) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if element, found := c.items[key]; found {
		item := element.Value.(*cacheItem)
		if timestamp, ok := item.value.(Time); ok {
			if Since(timestamp) < maxAge {
				c.list.MoveToFront(element)
				return item.value, true
			} else {
				c.list.Remove(element)
				delete(c.items, key)
			}
		}
		c.list.MoveToFront(element)
		return item.value, true
	}
	
	return nil, false
}

/* 
   Sorts domains by their URL count in descending order
*/
func SimpleSortByDomainCount(domains []string, countFunc func(string) int) []string {
	sort.Slice(domains, func(i, j int) bool {
		return countFunc(domains[i]) > countFunc(domains[j])
	})
	return domains
}

func SortByValue[T any, V int | float64 | string](items []T, valueFunc func(T) V) {
	sort.Slice(items, func(i, j int) bool {
		return valueFunc(items[i]) < valueFunc(items[j])
	})
}

func SortByValueDesc[T any, V int | float64 | string](items []T, valueFunc func(T) V) {
	sort.Slice(items, func(i, j int) bool {
		return valueFunc(items[i]) > valueFunc(items[j])
	})
}

/* 
   Divides a slice into chunks of the specified size
*/
func ChunkSlice[T any](slice []T, chunkSize int) [][]T {
	if chunkSize <= 0 {
		return [][]T{slice}
	}
	
	var chunks [][]T
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	
	return chunks
}

/* 
   Divides a slice into chunks based on a predicate function
*/
func ChunkBy[T any](items []T, predicate func(T, T) bool) [][]T {
	var result [][]T
	
	if len(items) == 0 {
		return result
	}
	
	currentChunk := []T{items[0]}
	
	for i := 1; i < len(items); i++ {
		if predicate(items[i-1], items[i]) {
			currentChunk = append(currentChunk, items[i])
		} else {
			result = append(result, currentChunk)
			currentChunk = []T{items[i]}
		}
	}
	
	if len(currentChunk) > 0 {
		result = append(result, currentChunk)
	}
	
	return result
}
