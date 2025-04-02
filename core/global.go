package core

import (
	"sync"
)

// Global variables used to track instances of core components
var (
	// Track all RegexManager instances
	globalRegexManagers     []*RegexManager
	globalRegexManagersLock sync.Mutex

	// Track all Processor instances
	globalProcessors     []*Processor
	globalProcessorsLock sync.Mutex
)

// RegisterRegexManager adds a RegexManager to the global registry
func RegisterRegexManager(rm *RegexManager) {
	if rm == nil {
		return
	}

	globalRegexManagersLock.Lock()
	defer globalRegexManagersLock.Unlock()
	
	globalRegexManagers = append(globalRegexManagers, rm)
}

// RegisterProcessor adds a Processor to the global registry
func RegisterProcessor(p *Processor) {
	if p == nil {
		return
	}

	globalProcessorsLock.Lock()
	defer globalProcessorsLock.Unlock()
	
	globalProcessors = append(globalProcessors, p)
}

// ResetGlobalInstances resets all globally registered instances
func ResetGlobalInstances() {
	// Reset RegexManagers
	globalRegexManagersLock.Lock()
	currentRegexManagers := globalRegexManagers
	globalRegexManagers = nil
	globalRegexManagersLock.Unlock()
	
	// Reset each manager separately (outside the lock to avoid deadlocks)
	for _, rm := range currentRegexManagers {
		if rm != nil {
			rm.Reset()
		}
	}
	
	// Reset Processors
	globalProcessorsLock.Lock()
	currentProcessors := globalProcessors
	globalProcessors = nil
	globalProcessorsLock.Unlock()
	
	// Reset each processor separately
	for _, p := range currentProcessors {
		if p != nil {
			p.ResetStats()
			if p.regexManager != nil {
				p.regexManager.Reset()
			}
		}
	}
}
