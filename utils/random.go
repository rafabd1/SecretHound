package utils

import (
	"math/rand"
	"sync"
	"time"
)

var (
	globalRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	randMutex  sync.Mutex
)

func RandomFloat() float64 {
	randMutex.Lock()
	defer randMutex.Unlock()
	return globalRand.Float64()
}

func RandomInt(min, max int) int {
	if min > max {
		min, max = max, min
	}
	
	randMutex.Lock()
	defer randMutex.Unlock()
	
	return min + globalRand.Intn(max-min+1)
}

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	
	randMutex.Lock()
	defer randMutex.Unlock()
	
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[globalRand.Intn(len(charset))]
	}
	
	return string(b)
}

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
	
	return userAgents[globalRand.Intn(len(userAgents))]
}

func Shuffle[T any](slice []T) {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	globalRand.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}

func RandomChoice[T any](slice []T) (T, bool) {
	if len(slice) == 0 {
		var zero T
		return zero, false
	}
	
	randMutex.Lock()
	defer randMutex.Unlock()
	
	return slice[globalRand.Intn(len(slice))], true
}

/* ShuffleSlice is an alias for Shuffle function for backward compatibility */
func ShuffleSlice[T any](slice []T) {
	Shuffle(slice)
}

func RandomBytes(length int) []byte {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	b := make([]byte, length)
	globalRand.Read(b)
	return b
}

func ResetRandomSeed() {
	randMutex.Lock()
	defer randMutex.Unlock()
	
	globalRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

/* WeightedChoice selects an item based on provided weights */
func WeightedChoice[T any](choices []T, weights []float64) (T, bool) {
	if len(choices) == 0 || len(choices) != len(weights) {
		var zero T
		return zero, false
	}
	
	var totalWeight float64
	for _, w := range weights {
		if w < 0 {
			var zero T
			return zero, false
		}
		totalWeight += w
	}
	
	if totalWeight <= 0 {
		var zero T
		return zero, false
	}
	
	randMutex.Lock()
	r := globalRand.Float64() * totalWeight
	randMutex.Unlock()
	
	var cumulativeWeight float64
	for i, w := range weights {
		cumulativeWeight += w
		if r < cumulativeWeight {
			return choices[i], true
		}
	}
	
	return choices[len(choices)-1], true
}
