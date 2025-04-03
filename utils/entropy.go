package utils

import (
	"math"
)

// CalculateEntropy calculates the Shannon entropy of a string
// Used to determine if a string has high entropy (randomness)
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	// Count frequency of each character
	freqs := make(map[rune]int)
	for _, r := range s {
		freqs[r]++
	}
	
	// Calculate entropy
	var entropy float64
	for _, count := range freqs {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	
	return entropy
}

// IsHighEntropy checks if a string has entropy above a threshold
func IsHighEntropy(s string, threshold float64) bool {
	return CalculateEntropy(s) > threshold
}
