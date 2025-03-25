package output

import (
	"sync"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
)

// Logger provides structured logging with queue management
type Logger struct {
	verbose bool
	mu      sync.Mutex
}

// NewLogger creates a new logger
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

// Debug logs a debug message (only shown in verbose mode)
func (l *Logger) Debug(format string, args ...interface{}) {
	// Será implementado posteriormente
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	// Será implementado posteriormente
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	// Será implementado posteriormente
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	// Será implementado posteriormente
}

// SecretFound logs a discovered secret
func (l *Logger) SecretFound(secretType, value, url string) {
	// Será implementado posteriormente
}
