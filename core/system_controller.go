package core

import (
    "runtime"
    "sync"
    "time"
)

var (
    systemLock sync.Mutex
    executionCounter int64
    
    // Component registries
    regexManagerRegistry = make(map[*RegexManager]bool)
    processorRegistry = make(map[*Processor]bool)
    
    regexManagerLock sync.RWMutex
    processorLock sync.RWMutex
)

/* 
   Returns a unique ID for the current execution cycle
*/
func GetUniqueExecutionID() int64 {
    systemLock.Lock()
    defer systemLock.Unlock()
    
    executionCounter++
    return executionCounter
}

/*
   Performs a complete refresh of the system state,
   including garbage collection and stabilization
*/
func ForceCompleteRefresh() {
    systemLock.Lock()
    defer systemLock.Unlock()
    
    runtime.GC()
    time.Sleep(50 * time.Millisecond)
}

/*
   Verifies if the system is in a clean state with no active components
*/
func IsSystemReady() bool {
    regexManagerLock.RLock()
    managerCount := len(regexManagerRegistry)
    regexManagerLock.RUnlock()
    
    processorLock.RLock()
    processorCount := len(processorRegistry)
    processorLock.RUnlock()
    
    return managerCount == 0 && processorCount == 0
}
