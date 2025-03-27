package output

import (
	"fmt"
	"os"
	"sync"

	"github.com/secrethound/utils"
)

// TerminalController provides centralized control for terminal output
// to coordinate between log messages and progress bar rendering
type TerminalController struct {
    mu              sync.Mutex
    outputMu        sync.Mutex
    isActive        bool
    isTerminal      bool
    hasProgressBar  bool 
}

// Global singleton instance
var (
    terminalController *TerminalController
    once               sync.Once
)

// GetTerminalController returns the singleton terminal controller instance
func GetTerminalController() *TerminalController {
    once.Do(func() {
        // Check if stderr is a terminal during initialization
        isTerminal := utils.IsTerminal(os.Stderr.Fd())
        
        terminalController = &TerminalController{
            isActive:       true,
            isTerminal:     isTerminal,
            hasProgressBar: false,
        }
    })
    return terminalController
}

// BeginOutput acquires the output lock for atomic terminal operations
func (tc *TerminalController) BeginOutput() {
    tc.outputMu.Lock()
}

// EndOutput releases the output lock
func (tc *TerminalController) EndOutput() {
    tc.outputMu.Unlock()
}

// SetProgressBarActive configures whether a progress bar is currently active
func (tc *TerminalController) SetProgressBarActive(active bool) {
    tc.mu.Lock()
    tc.hasProgressBar = active
    tc.mu.Unlock()
}

// HasProgressBar returns whether a progress bar is currently active
func (tc *TerminalController) HasProgressBar() bool {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.hasProgressBar
}

// ClearLine clears the current terminal line
func (tc *TerminalController) ClearLine() {
    if tc.isTerminal {
        fmt.Fprint(os.Stderr, "\033[2K\r")
    }
}

// CoordinateOutput executes a function with exclusive access to the terminal
func (tc *TerminalController) CoordinateOutput(fn func()) {
    tc.BeginOutput()
    defer tc.EndOutput()
    
    // Clear the current line for clean output
    tc.ClearLine()
    
    // Execute the output function
    fn()
}

// IsTerminal returns whether the output is connected to a terminal
func (tc *TerminalController) IsTerminal() bool {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.isTerminal
}