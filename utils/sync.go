package utils

import (
	"sync"
	"sync/atomic"
	"time"
)

// SafeCounter is a thread-safe counter
type SafeCounter struct {
	count int64
}

// NewSafeCounter creates a new safe counter
func NewSafeCounter() *SafeCounter {
	return &SafeCounter{count: 0}
}

// Increment increments the counter
func (sc *SafeCounter) Increment() int64 {
	return atomic.AddInt64(&sc.count, 1)
}

// Decrement decrements the counter
func (sc *SafeCounter) Decrement() int64 {
	return atomic.AddInt64(&sc.count, -1)
}

// Add adds a value to the counter
func (sc *SafeCounter) Add(value int64) int64 {
	return atomic.AddInt64(&sc.count, value)
}

// Value returns the current value of the counter
func (sc *SafeCounter) Value() int64 {
	return atomic.LoadInt64(&sc.count)
}

// Reset resets the counter to zero
func (sc *SafeCounter) Reset() {
	atomic.StoreInt64(&sc.count, 0)
}

// SafeMap is a thread-safe map
type SafeMap[K comparable, V any] struct {
	data map[K]V
	mu   sync.RWMutex
}

// NewSafeMap creates a new safe map
func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{
		data: make(map[K]V),
	}
}

// Set sets a key-value pair in the map
func (sm *SafeMap[K, V]) Set(key K, value V) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data[key] = value
}

// Get gets a value from the map
func (sm *SafeMap[K, V]) Get(key K) (V, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	value, ok := sm.data[key]
	return value, ok
}

// Delete deletes a key from the map
func (sm *SafeMap[K, V]) Delete(key K) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.data, key)
}

// Has checks if a key exists in the map
func (sm *SafeMap[K, V]) Has(key K) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.data[key]
	return ok
}

// Keys returns all keys in the map
func (sm *SafeMap[K, V]) Keys() []K {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	keys := make([]K, 0, len(sm.data))
	for k := range sm.data {
		keys = append(keys, k)
	}
	return keys
}

// Values returns all values in the map
func (sm *SafeMap[K, V]) Values() []V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	values := make([]V, 0, len(sm.data))
	for _, v := range sm.data {
		values = append(values, v)
	}
	return values
}

// Len returns the number of items in the map
func (sm *SafeMap[K, V]) Len() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.data)
}

// Clear clears the map
func (sm *SafeMap[K, V]) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.data = make(map[K]V)
}

// Copy creates a copy of the map
func (sm *SafeMap[K, V]) Copy() map[K]V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copy := make(map[K]V, len(sm.data))
	for k, v := range sm.data {
		copy[k] = v
	}
	return copy
}

// Throttle creates a function that throttles calls to the given function
func Throttle(f func(), delay time.Duration) func() {
	var lastCall time.Time
	var mu sync.Mutex
	
	return func() {
		mu.Lock()
		defer mu.Unlock()
		
		now := time.Now()
		if now.Sub(lastCall) >= delay {
			lastCall = now
			f()
		}
	}
}

// Debounce creates a function that debounces calls to the given function
func Debounce(f func(), delay time.Duration) func() {
	var timer *time.Timer
	var mu sync.Mutex
	
	return func() {
		mu.Lock()
		defer mu.Unlock()
		
		if timer != nil {
			timer.Stop()
		}
		
		timer = time.AfterFunc(delay, f)
	}
}

// RunWithTimeout runs a function with a timeout
func RunWithTimeout(f func() (interface{}, error), timeout time.Duration) (interface{}, error) {
	resultCh := make(chan struct {
		result interface{}
		err    error
	}, 1)
	
	go func() {
		result, err := f()
		resultCh <- struct {
			result interface{}
			err    error
		}{result, err}
	}()
	
	select {
	case r := <-resultCh:
		return r.result, r.err
	case <-time.After(timeout):
		return nil, NewError(TemporaryError, "operation timed out", nil)
	}
}
