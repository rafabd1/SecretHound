package utils

import (
	"sort"
)

// SimpleSortByDomainCount sorts domains by their URL count in descending order
func SimpleSortByDomainCount(domains []string, countFunc func(string) int) []string {
	sort.Slice(domains, func(i, j int) bool {
		return countFunc(domains[i]) > countFunc(domains[j])
	})
	return domains
}

// SortByValue sorts a slice based on values returned by a value function
func SortByValue[T any, V int | float64 | string](items []T, valueFunc func(T) V) {
	sort.Slice(items, func(i, j int) bool {
		return valueFunc(items[i]) < valueFunc(items[j])
	})
}

// SortByValueDesc sorts a slice in descending order based on values returned by a value function
func SortByValueDesc[T any, V int | float64 | string](items []T, valueFunc func(T) V) {
	sort.Slice(items, func(i, j int) bool {
		return valueFunc(items[i]) > valueFunc(items[j])
	})
}

// ChunkBy divides a slice into chunks based on a predicate function
func ChunkBy[T any](items []T, predicate func(T, T) bool) [][]T {
	var result [][]T
	
	if len(items) == 0 {
		return result
	}
	
	// Start with the first item
	currentChunk := []T{items[0]}
	
	for i := 1; i < len(items); i++ {
		// If the predicate returns true, add to current chunk
		if predicate(items[i-1], items[i]) {
			currentChunk = append(currentChunk, items[i])
		} else {
			// Otherwise, start a new chunk
			result = append(result, currentChunk)
			currentChunk = []T{items[i]}
		}
	}
	
	// Add the last chunk
	if len(currentChunk) > 0 {
		result = append(result, currentChunk)
	}
	
	return result
}
