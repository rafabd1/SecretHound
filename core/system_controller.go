package core

import (
	"runtime"
	"sync"
	"time"
)

var (
    // Global lock for entire system operation
    systemLock sync.Mutex
    
    // Execution counter to ensure uniqueness
    executionCounter int64
    
    // Component registries
    regexManagerRegistry = make(map[*RegexManager]bool)
    processorRegistry = make(map[*Processor]bool)
    
    // Registry locks
    regexManagerLock sync.RWMutex
    processorLock sync.RWMutex
)

// GetUniqueExecutionID returns a unique ID for this execution
func GetUniqueExecutionID() int64 {
    systemLock.Lock()
    defer systemLock.Unlock()
    
    executionCounter++
    return executionCounter
}

// ForceCompleteRefresh performs a complete refresh of the system state
func ForceCompleteRefresh() {
    // Acquire global system lock to prevent any operations during refresh
    systemLock.Lock()
    defer systemLock.Unlock()
    
    // Force garbage collection to clean up memory
    runtime.GC()
    
    // Wait for system to stabilize
    time.Sleep(50 * time.Millisecond)
}

// IsSystemReady checks if the system is in a clean state
func IsSystemReady() bool {
    regexManagerLock.RLock()
    managerCount := len(regexManagerRegistry)
    regexManagerLock.RUnlock()
    
    processorLock.RLock()
    processorCount := len(processorRegistry)
    processorLock.RUnlock()
    
    return managerCount == 0 && processorCount == 0
}
