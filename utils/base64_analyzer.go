package utils

import (
    "encoding/base64"
    "strings"
)

// Common patterns for base64 content types
var (
    base64Prefixes = []string{
        "data:image/",
        "data:application/",
        "data:text/",
        "data:font/",
        "data:audio/",
        "data:video/",
    }
    
    // Patterns that indicate binary data, not text secrets
    binaryDataIndicators = []byte{0x00, 0xFF, 0xD8, 0x89, 0x50, 0x4D, 0x42, 0x4C}
)

func IsBase64Encoded(str string) bool {
    if len(str) % 4 != 0 && !strings.HasSuffix(str, "=") && !strings.HasSuffix(str, "==") {
        return false
    }
    
    for _, c := range str {
        if !(('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || 
            ('0' <= c && c <= '9') || c == '+' || c == '/' || c == '=') {
            return false
        }
    }
    
    _, err := base64.StdEncoding.DecodeString(str)
    return err == nil
}

func IsDataURI(str string) bool {
    for _, prefix := range base64Prefixes {
        if strings.HasPrefix(str, prefix) && strings.Contains(str, ";base64,") {
            return true
        }
    }
    return false
}

func IsLikelyBinaryData(str string) bool {
    data, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return false
    }
    
    for _, prefix := range binaryDataIndicators {
        if len(data) > 0 && data[0] == prefix {
            return true
        }
    }
    
    nonPrintable := 0
    for i := 0; i < len(data) && i < 100; i++ {
        if data[i] < 32 || data[i] > 126 {
            nonPrintable++		}
    }
    
    threshold := 20
    if len(data) < 100 {
        threshold = len(data) / 5
    }
    
    return nonPrintable > threshold
}

/* 
    Checks if a string is likely a fragment of base64 data based on common prefixes and patterns
*/
func IsLikelyBase64Fragment(str string) bool {
    commonPrefixes := []string{
        "AAA", "eJy", "base64", "iVBOR", "PHN2", "PD94", "PCFET", "ZXlK",
        "77u/", "QUJD", "Qk1X", "QkdH", "AoAEA", "d2lkdGg", "aGVpZ2h0",
    }
    
    for _, prefix := range commonPrefixes {
        if strings.HasPrefix(str, prefix) || strings.Contains(str, prefix) {
            return true
        }
    }
    
    patternIndicators := []string{
        "AAAA", "////", "----", "abcd", "0000", "1111", "2222", "eeee",
        "ffff", "9999",
    }
    
    patternCount := 0
    for _, pattern := range patternIndicators {
        if strings.Contains(str, pattern) {
            patternCount++
        }
    }
    
    return patternCount >= 2
}

/*
    Determines if a base64 encoded string likely contains a secret value
    by examining the decoded content for secret-related keywords
*/
func IsLikelySecretInBase64(str string) bool {
    if IsLikelyBase64Fragment(str) {
        return false
    }
    
    if !IsBase64Encoded(str) || len(str) < 20 || len(str) > 1000 {
        return false
    }
    
    if IsDataURI(str) || IsLikelyBinaryData(str) {
        return false
    }
    
    data, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return false
    }
    
    dataStr := string(data)
    secretKeywords := []string{
        "key", "secret", "token", "password", "apikey", "api_key", 
        "auth", "credential", "private", "access", "token",
    }
    
    for _, keyword := range secretKeywords {
        if strings.Contains(strings.ToLower(dataStr), keyword) {
            return true
        }
    }
    
    return false
}
