package utils

import (
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// Aliases para compatibilidade e redução de imports
type Time = time.Time
type Duration = time.Duration

// min returns the smaller of a and b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of a and b
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Now returns the current time
func Now() Time {
	return time.Now()
}

// Since returns the time elapsed since t
func Since(t Time) Duration {
	return time.Since(t)
}

// Sleep pauses the current goroutine for at least the duration d
func Sleep(d Duration) {
	time.Sleep(d)
}

// After waits for the duration to elapse and then sends the current time on the returned channel
func After(d Duration) <-chan Time {
	return time.After(d)
}

// AtomicAddInt64 atomically adds delta to *addr and returns the new value
func AtomicAddInt64(addr *int64, delta int64) int64 {
	return atomic.AddInt64(addr, delta)
}

// AtomicLoadInt64 atomically loads *addr
func AtomicLoadInt64(addr *int64) int64 {
	return atomic.LoadInt64(addr)
}

// AtomicStoreInt64 atomically stores val into *addr
func AtomicStoreInt64(addr *int64, val int64) {
	atomic.StoreInt64(addr, val)
}

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

// IsTerminal checks if the given file descriptor is a terminal
func IsTerminal(fd uintptr) bool {
	// On Windows, use environment variables as fallback
	if IsWindows() {
		// Simple heuristic for Windows terminal detection
		return os.Getenv("TERM") != "" || 
			   os.Getenv("WT_SESSION") != "" || // Windows Terminal
			   os.Getenv("CMDER_ROOT") != "" || // Cmder
			   os.Getenv("SESSIONNAME") != ""   // Terminal session exists
	}
	
	// For Unix systems, use a simplified check
	// This is a simplified implementation, ideally we'd use isatty
	stat, err := os.Stat("/dev/tty")
	return err == nil && stat.Mode()&os.ModeCharDevice != 0
}
