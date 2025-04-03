package utils

import (
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

type Time = time.Time
type Duration = time.Duration

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Now() Time {
	return time.Now()
}

func Since(t Time) Duration {
	return time.Since(t)
}

func Sleep(d Duration) {
	time.Sleep(d)
}

func After(d Duration) <-chan Time {
	return time.After(d)
}

func AtomicAddInt64(addr *int64, delta int64) int64 {
	return atomic.AddInt64(addr, delta)
}

func AtomicLoadInt64(addr *int64) int64 {
	return atomic.LoadInt64(addr)
}

func AtomicStoreInt64(addr *int64, val int64) {
	atomic.StoreInt64(addr, val)
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func IsLinux() bool {
	return runtime.GOOS == "linux"
}

func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

func GetCurrentMemoryUsage() uint64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return mem.Alloc
}

func NumCPU() int {
	return runtime.NumCPU()
}

/* 
   Checks if the given file descriptor is a terminal using OS-specific approaches
*/
func IsTerminal(fd uintptr) bool {
	if IsWindows() {
		return os.Getenv("TERM") != "" || 
			   os.Getenv("WT_SESSION") != "" || 
			   os.Getenv("CMDER_ROOT") != "" || 
			   os.Getenv("SESSIONNAME") != ""
	}
	
	stat, err := os.Stat("/dev/tty")
	return err == nil && stat.Mode()&os.ModeCharDevice != 0
}
