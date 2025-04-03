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

// IsLikelyRandomPassword checks if a string looks like a random password or token
// rather than natural language or code
func IsLikelyRandomPassword(s string) bool {
	// Calculate entropy
	entropy := CalculateEntropy(s)
	
	// Most random passwords/tokens have high entropy
	if entropy < 3.5 {
		return false
	}
	
	// CSS variables and class names are often high entropy but not secrets
	if IsLikelyCSS(s) {
		return false
	}
	
	// Internationalization keys are not secrets
	if IsLikelyI18nKey(s) {
		return false
	}
	
	// Function names are not secrets
	if IsLikelyFunctionName(s) {
		return false
	}
	
	// URLs and documentation references are not secrets
	if IsLikelyUrl(s) || IsLikelyDocumentation(s, "") {
		return false
	}
	
	// If string has many digit patterns or repeating character sequences, likely not a secret
	if HasRepeatedCharacterPattern(s) {
		return false
	}
	
	// If it's a clean UUID, it's an identifier not a secret
	if IsUUID(s) {
		return false
	}
	
	// Check character distribution
	charTypes := countCharacterTypes(s)
	
	// Most good passwords use multiple character types
	if charTypes < 2 {
		return false
	}
	
	return true
}

// countCharacterTypes counts how many types of characters are in the string
func countCharacterTypes(s string) int {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		} else if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}
	
	types := 0
	if hasLower {
		types++
	}
	if hasUpper {
		types++
	}
	if hasDigit {
		types++
	}
	if hasSpecial {
		types++
	}
	
	return types
}
