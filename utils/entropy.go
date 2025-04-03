package utils

import (
	"math"
)

func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freqs := make(map[rune]int)
	for _, r := range s {
		freqs[r]++
	}
	
	var entropy float64
	for _, count := range freqs {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	
	return entropy
}

func IsHighEntropy(s string, threshold float64) bool {
	return CalculateEntropy(s) > threshold
}

/* 
	Evaluates if a string has characteristics of a random password or security token
*/
func IsLikelyRandomPassword(s string) bool {
	entropy := CalculateEntropy(s)
	
	if entropy < 3.5 {
		return false
	}
	
	if IsLikelyCSS(s) || IsLikelyI18nKey(s) || 
		IsLikelyFunctionName(s) || IsLikelyUrl(s) || 
		IsLikelyDocumentation(s, "") {
		return false
	}
	
	if HasRepeatedCharacterPattern(s) {
		return false
	}
	
	if IsUUID(s) {
		return false
	}
	
	charTypes := countCharacterTypes(s)
	
	return charTypes >= 2
}

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
