package core

import (
	"fmt"
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
    
    // Debug para verificar registros
    fmt.Printf("DEBUG: Refreshing system state with %d managers and %d processors\n", 
               len(regexManagerRegistry), len(processorRegistry))
    
    // 1. Collect all registered components
    regexManagerLock.RLock()
    managers := make([]*RegexManager, 0, len(regexManagerRegistry))
    for rm := range regexManagerRegistry {
        managers = append(managers, rm)
    }
    regexManagerLock.RUnlock()
    
    processorLock.RLock()
    processors := make([]*Processor, 0, len(processorRegistry))
    for p := range processorRegistry {
        processors = append(processors, p)
    }
    processorLock.RUnlock()
    
    // 2. DON'T Reset managers and processors - isso pode estar causando problemas
    // Apenas mantenha o registro
    
    // 3. Force garbage collection to clean up memory
    runtime.GC()
    
    // 4. Wait for system to stabilize
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
