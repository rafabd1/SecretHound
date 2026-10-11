package utils

import (
	"math"
	"unicode/utf8"
)

/*
CalculateEntropy computes Shannon entropy in bits/symbol for a UTF-8 string.
*/
func CalculateEntropy(s string) float64 {
	runeCount := utf8.RuneCountInString(s)
	if runeCount == 0 {
		return 0
	}

	freqs := make(map[rune]int)
	for _, r := range s {
		freqs[r]++
	}

	var entropy float64
	for _, count := range freqs {
		p := float64(count) / float64(runeCount)
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func IsHighEntropy(s string, threshold float64) bool {
	return CalculateEntropy(s) >= threshold
}

/*
IsLikelyRandomSecret checks only properties of the candidate's randomness.
Code, documentation, and identifier signals belong to the pattern-aware
validation layer, where they can lower confidence without discarding a
provider-shaped credential before its format is considered.
*/
func IsLikelyRandomSecret(s string, minEntropy float64, minLength int) bool {
	if len(s) < minLength {
		return false
	}

	if HasRepeatedCharacterPattern(s) {
		return false
	}

	if countCharacterTypes(s) < 2 {
		return false
	}

	return IsHighEntropy(s, minEntropy)
}

func IsLikelyRandomPassword(s string) bool {
	return IsLikelyRandomSecret(s, 3.5, 12)
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
