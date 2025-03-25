package utils

import (
	"fmt"
)

// ErrorType represents the type of error
type ErrorType int

const (
	NetworkError ErrorType = iota
	ConfigError
	ProcessingError
	RateLimitError
	WAFError
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
