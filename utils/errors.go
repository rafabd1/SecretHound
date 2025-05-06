package utils

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
)

var (
	ErrTimeout = errors.New("operation timed out")
	ErrCanceled = errors.New("operation was canceled")
	ErrNotFound = errors.New("resource not found")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrCertificate = errors.New("certificate validation failed")
)

type ErrorType int

const (
	NetworkError ErrorType = iota
	ConfigError
	ProcessingError
	RateLimitError
	WAFError
	TemporaryError
	CertificateError
)

type AppError struct {
	Type    ErrorType
	Message string
	Err     error
	StatusCode int
}

func NewError(errType ErrorType, message string, err error) *AppError {
	return &AppError{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Is(target error) bool {
	t, ok := target.(*AppError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

func (e *AppError) Unwrap() error {
	return e.Err
}

/* 
   Checks if the provided error is a network-related error
*/
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for url.Error type, common for network issues
	if _, ok := err.(*url.Error); ok {
		return true
	}

	// Check for specific syscall errors (more robust)
	if opError, ok := err.(*net.OpError); ok {
		if sysErr, ok := opError.Err.(*os.SyscallError); ok {
			syscallName := strings.ToLower(sysErr.Syscall)
			// Common network-related syscalls
			if syscallName == "connect" || syscallName == "read" || syscallName == "write" {
				// Check for specific network errors within the syscall error
				switch sysErr.Err {
				case syscall.ECONNREFUSED,
					syscall.ECONNRESET,
					syscall.ETIMEDOUT,
					syscall.ENETUNREACH,
					syscall.EHOSTUNREACH:
					return true
				}
			}
		}
		// Also consider general net.OpError as network error if not syscall specific
		return true 
	}
	
	// Check for AppError indicating a network problem (e.g., timeout)
	if appErr, ok := err.(*AppError); ok {
		if appErr.StatusCode == 0 && strings.Contains(strings.ToLower(appErr.Message), "timeout") {
            return true
        }
	}

	// Generic checks for common network error messages
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "no such host") ||
		strings.Contains(errMsg, "network is unreachable")
}

/* 
   Determines if an error is related to rate limiting based on type or common keywords
*/
func IsRateLimitError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == RateLimitError
	}
	
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

/* 
   Identifies if an error is related to Web Application Firewall restrictions
*/
func IsWAFError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == WAFError
	}
	
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

/* 
   Checks if an error is temporary and potentially retryable
*/
func IsTemporaryError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Type == TemporaryError
	}
	
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() {
		return true
	}
	
	errStr := strings.ToLower(err.Error())
	tempKeywords := []string{
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

/* 
   Determines if an error is related to timeout conditions
*/
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	
	if errors.Is(err, ErrTimeout) {
		return true
	}
	
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) && appErr.Type == NetworkError {
		timeoutIndicators := []string{
			"timeout",
			"timed out",
			"deadline exceeded",
			"context deadline exceeded",
		}
		
		for _, indicator := range timeoutIndicators {
			if strings.Contains(strings.ToLower(appErr.Error()), indicator) {
				return true
			}
		}
	}
	
	errStr := err.Error()
	return strings.Contains(strings.ToLower(errStr), "timeout") ||
		strings.Contains(strings.ToLower(errStr), "timed out") ||
		strings.Contains(strings.ToLower(errStr), "deadline exceeded")
}

func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

/* 
   Checks if an error was caused by context cancellation
*/
func IsContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	
	return errors.Is(err, ErrCanceled) ||
		strings.Contains(strings.ToLower(err.Error()), "context canceled") ||
		strings.Contains(strings.ToLower(err.Error()), "operation was canceled")
}

/* 
   Checks if an error is related to certificate validation issues
*/
func IsCertificateError(err error) bool {
	if err == nil {
		return false
	}
	
	if errors.Is(err, ErrCertificate) {
		return true
	}
	
	errStr := strings.ToLower(err.Error())
	certErrors := []string{
		"certificate",
		"x509",
		"tls",
		"ssl",
		"verify",
		"validation",
		"hostname",
		"certificate is valid for",
		"not valid for",
		"self-signed",
		"cert",
	}
	
	for _, keyword := range certErrors {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) && appErr.Type == CertificateError {
		return true
	}
	
	return false
}

// IsNotFoundError checks if an error indicates a 404 status code.
func IsNotFoundError(err error) bool {
	appErr, ok := err.(*AppError)
	return ok && appErr.StatusCode == 404
}
