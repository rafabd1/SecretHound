package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// IsWindows checks if the current OS is Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsLinux checks if the current OS is Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsMacOS checks if the current OS is macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// CreateDirIfNotExists creates a directory if it doesn't exist
func CreateDirIfNotExists(path string) error {
	if !DirExists(path) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// GenerateTempFileName generates a temporary file name
func GenerateTempFileName(prefix, suffix string) string {
	timestamp := time.Now().UnixNano()
	random := RandomString(8)
	return fmt.Sprintf("%s_%d_%s%s", prefix, timestamp, random, suffix)
}

// HashString returns a SHA-256 hash of a string
func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// TruncateString truncates a string to maxLength
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	
	return s[:maxLength-3] + "..."
}

// FormatByteSize formats a byte size into a human-readable string
func FormatByteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats a duration in a human-readable format
func FormatDuration(d time.Duration) string {
	if d.Seconds() < 60.0 {
		return fmt.Sprintf("%.2f seconds", d.Seconds())
	}
	
	if d.Minutes() < 60.0 {
		seconds := d.Seconds() - float64(int(d.Minutes())*60)
		return fmt.Sprintf("%d minutes %.2f seconds", int(d.Minutes()), seconds)
	}
	
	hours := int(d.Hours())
	minutes := int(d.Minutes()) - hours*60
	seconds := d.Seconds() - float64(hours*3600+minutes*60)
	return fmt.Sprintf("%d hours %d minutes %.2f seconds", hours, minutes, seconds)
}

// SplitLines splits a string into lines
func SplitLines(s string) []string {
	// Split by Unix, Windows, and old Mac line endings
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"), "\n")
	
	// Remove empty lines
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			result = append(result, line)
		}
	}
	
	return result
}

// ChunkSlice divides a slice into chunks of the specified size
func ChunkSlice[T any](slice []T, chunkSize int) [][]T {
	if chunkSize <= 0 {
		return [][]T{slice}
	}
	
	var chunks [][]T
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	
	return chunks
}

// GetCurrentMemoryUsage returns the current memory usage of the program
func GetCurrentMemoryUsage() uint64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return mem.Alloc
}

// NumCPU returns the number of logical CPUs usable by the current process
func NumCPU() int {
	return runtime.NumCPU()
}

// HasPrefix checks if any of the prefixes match the string
func HasAnyPrefix(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// HasSuffix checks if any of the suffixes match the string
func HasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// Contains checks if any of the substrings are in the string
func ContainsAny(s string, substrings ...string) bool {
	for _, substring := range substrings {
		if strings.Contains(s, substring) {
			return true
		}
	}
	return false
}

// IsTerminal checks if the given file descriptor is a terminal
func IsTerminal(fd uintptr) bool {
	// On Windows, we need to use syscall from the golang.org/x/sys/windows package
	// For Unix-like systems, we'd use isatty from golang.org/x/sys/unix
	// For simplicity, we'll just check for colorable output
	// If we want exact terminal detection, we'd need to add the sys packages
	
	if IsWindows() {
		// On Windows we can use this as a fallback check
		// This won't detect all terminal types but works for common cases
		return os.Getenv("TERM") != "" || 
			   os.Getenv("WT_SESSION") != "" || // Windows Terminal
			   os.Getenv("CMDER_ROOT") != "" || // Cmder
			   os.Getenv("SESSIONNAME") != "" // Terminal session exists
	}
	
	// For Unix-like systems (simplified check)
	return os.Getenv("TERM") != ""
}
