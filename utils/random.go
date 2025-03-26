package utils

import (
	"math/rand"
	"sync"
	"time"
)

var (
	randSource = rand.NewSource(time.Now().UnixNano())
	randGen    = rand.New(randSource)
	randMutex  sync.Mutex
)

// RandomFloat returns a random float64 between 0.0 and 1.0
func RandomFloat() float64 {
	randMutex.Lock()
	defer randMutex.Unlock()
	return randGen.Float64()
}

// RandomInt returns a random integer between min and max (inclusive)
func RandomInt(min, max int) int {
	if min >= max {
		return min
	}
	
	randMutex.Lock()
	defer randMutex.Unlock()
	return randGen.Intn(max-min+1) + min
}

// RandomString generates a random string of the specified length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	
	randMutex.Lock()
	defer randMutex.Unlock()
	
	for i := range result {
		result[i] = charset[randGen.Intn(len(charset))]
	}
	
	return string(result)
}

// RandomUserAgent returns a random user agent string
func RandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}
	
	randMutex.Lock()
	defer randMutex.Unlock()
	return userAgents[randGen.Intn(len(userAgents))]
}

// Shuffle randomly shuffles a slice
func Shuffle(slice []string) {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	rand.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}

// RandomChoice randomly selects an element from a slice
func RandomChoice[T any](items []T) T {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	if len(items) == 0 {
		var zero T
		return zero
	}
	
	return items[randGen.Intn(len(items))]
}

// ShuffleSlice randomly shuffles a slice in-place
func ShuffleSlice[T any](items []T) {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	for i := range items {
		j := randGen.Intn(i + 1)
		items[i], items[j] = items[j], items[i]
	}
}
