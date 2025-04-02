package utils

import (
	"errors"
	"fmt"
	"strings"
	"net"
)

// ErrorType represents the type of error
type ErrorType int

const (
	NetworkError ErrorType = iota
	ConfigError
	ProcessingError
	RateLimitError
	WAFError
	TemporaryError
)

// AppError represents an application error
type AppError struct {
	Type    ErrorType
	Message string
	Err     error
}

// NewError creates a new application error
func NewError(errType ErrorType, message string, err error) *AppError {
	return &AppError{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}

// Error returns the error message
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Is implements the errors.Is interface
func (e *AppError) Is(target error) bool {
	t, ok := target.(*AppError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

// IsNetworkError checks if an error is a network error
func IsNetworkError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == NetworkError
	}
	return false
}

// IsRateLimitError checks if an error is a rate limit error
func IsRateLimitError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == RateLimitError
	}
	
	// Also check for common rate limit error messages
	errStr := strings.ToLower(err.Error())
	rateLimitKeywords := []string{
		"rate limit",
		"too many requests",
		"throttle",
		"429",
	}
	
	for _, keyword := range rateLimitKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}
	
	return false
}

// IsWAFError checks if an error is a WAF error
func IsWAFError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == WAFError
	}
	
	// Also check for common WAF error messages
	errStr := strings.ToLower(err.Error())
	wafKeywords := []string{
		"waf",
		"firewall",
		"blocked",
		"security",
		"403 forbidden",
	}
	
	for _, keyword := range wafKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}
	
	return false
}

// IsTemporaryError checks if an error is temporary and retryable
func IsTemporaryError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == TemporaryError
	}
	
	// Also check for common temporary error messages
	errStr := strings.ToLower(err.Error())
	tempKeywords := []string{
		"timeout",
		"temporary",
		"retriable",
		"connection reset",
		"connection refused",
		"network is unreachable",
		"server is busy",
		"try again",
		"temporary failure",
	}
	
	for _, keyword := range tempKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}
	
	return false
}

func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for net.Error with Timeout() method
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	
	// Check wrapped errors
	var wrapErr *AppError
	if errors.As(err, &wrapErr) && wrapErr.Type == NetworkError {
		// Check the message for timeout indicators
		timeoutIndicators := []string{
			"timeout",
			"timed out",
			"deadline exceeded",
			"context deadline exceeded",
		}
		
		for _, indicator := range timeoutIndicators {
			if strings.Contains(strings.ToLower(wrapErr.Error()), indicator) {
				return true
			}
		}
	}
	
	// Last resort: check error string
	errStr := err.Error()
	return strings.Contains(strings.ToLower(errStr), "timeout") ||
		strings.Contains(strings.ToLower(errStr), "timed out") ||
		strings.Contains(strings.ToLower(errStr), "deadline exceeded")
}
