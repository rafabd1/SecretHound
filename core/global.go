package core

import (
	"sync"
)

// Global registry variables
var (
	globalRegexManagers     []*RegexManager
	globalRegexManagersLock sync.Mutex

	globalProcessors     []*Processor
	globalProcessorsLock sync.Mutex
)

/* 
   Adds a RegexManager to the global registry
*/
func RegisterRegexManager(rm *RegexManager) {
	if rm == nil {
		return
	}

	globalRegexManagersLock.Lock()
	defer globalRegexManagersLock.Unlock()
	
	globalRegexManagers = append(globalRegexManagers, rm)
}

/* 
   Adds a Processor to the global registry
*/
func RegisterProcessor(p *Processor) {
	if p == nil {
		return
	}

	globalProcessorsLock.Lock()
	defer globalProcessorsLock.Unlock()
	
	globalProcessors = append(globalProcessors, p)
}

/*
   Resets all globally registered instances and their internal state
*/
func ResetGlobalInstances() {
	globalRegexManagersLock.Lock()
	currentRegexManagers := globalRegexManagers
	globalRegexManagers = nil
	globalRegexManagersLock.Unlock()
	
	for _, rm := range currentRegexManagers {
		if rm != nil {
			rm.Reset()
		}
	}
	
	globalProcessorsLock.Lock()
	currentProcessors := globalProcessors
	globalProcessors = nil
	globalProcessorsLock.Unlock()
	
	for _, p := range currentProcessors {
		if p != nil {
			p.ResetStats()
			if p.regexManager != nil {
				p.regexManager.Reset()
			}
		}
	}
}
