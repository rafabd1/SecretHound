package utils

import (
	"sync"
)

type SafeCounter struct {
	count int64
}

func NewSafeCounter() *SafeCounter {
	return &SafeCounter{count: 0}
}

func (sc *SafeCounter) Increment() int64 {
	return AtomicAddInt64(&sc.count, 1)
}

func (sc *SafeCounter) Decrement() int64 {
	return AtomicAddInt64(&sc.count, -1)
}

func (sc *SafeCounter) Add(value int64) int64 {
	return AtomicAddInt64(&sc.count, value)
}

func (sc *SafeCounter) Value() int64 {
	return AtomicLoadInt64(&sc.count)
}

func (sc *SafeCounter) Reset() {
	AtomicStoreInt64(&sc.count, 0)
}

type SafeMap[K comparable, V any] struct {
	data map[K]V
	mu   sync.RWMutex
}

func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{
		data: make(map[K]V),
	}
}

func (sm *SafeMap[K, V]) Get(key K) (V, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	val, ok := sm.data[key]
	return val, ok
}

func (sm *SafeMap[K, V]) Set(key K, value V) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data[key] = value
}

func (sm *SafeMap[K, V]) Delete(key K) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.data, key)
}

func (sm *SafeMap[K, V]) Has(key K) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.data[key]
	return ok
}

func (sm *SafeMap[K, V]) Keys() []K {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	keys := make([]K, 0, len(sm.data))
	for k := range sm.data {
		keys = append(keys, k)
	}
	return keys
}

func (sm *SafeMap[K, V]) Values() []V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	values := make([]V, 0, len(sm.data))
	for _, v := range sm.data {
		values = append(values, v)
	}
	return values
}

func (sm *SafeMap[K, V]) Len() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.data)
}

func (sm *SafeMap[K, V]) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data = make(map[K]V)
}

/* 
	Returns a deep copy of the map's current state
*/
func (sm *SafeMap[K, V]) Snapshot() map[K]V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	result := make(map[K]V, len(sm.data))
	for k, v := range sm.data {
		result[k] = v
	}
	
	return result
}
