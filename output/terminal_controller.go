package output

import (
    "fmt"
    "os"
    "sync"

    "github.com/rafabd1/SecretHound/utils"
)

type TerminalController struct {
    mu              sync.Mutex
    outputMu        sync.Mutex
    isActive        bool
    isTerminal      bool
    hasProgressBar  bool 
}

var (
    terminalController *TerminalController
    once               sync.Once
)

func GetTerminalController() *TerminalController {
    once.Do(func() {
        isTerminal := utils.IsTerminal(os.Stderr.Fd())
        
        terminalController = &TerminalController{
            isActive:       true,
            isTerminal:     isTerminal,
            hasProgressBar: false,
        }
    })
    return terminalController
}

func (tc *TerminalController) BeginOutput() {
    tc.outputMu.Lock()
}

func (tc *TerminalController) EndOutput() {
    tc.outputMu.Unlock()
}

func (tc *TerminalController) SetProgressBarActive(active bool) {
    tc.mu.Lock()
    tc.hasProgressBar = active
    tc.mu.Unlock()
}

func (tc *TerminalController) HasProgressBar() bool {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.hasProgressBar
}

/* 
    Clears the current terminal line if output is to a terminal
*/
func (tc *TerminalController) ClearLine() {
    if tc.isTerminal {
        fmt.Fprint(os.Stderr, "\033[2K\r")
    }
}

/* 
    Executes a function with exclusive access to the terminal
*/
func (tc *TerminalController) CoordinateOutput(fn func()) {
    tc.BeginOutput()
    defer tc.EndOutput()
    
    tc.ClearLine()
    
    fn()
}

func (tc *TerminalController) IsTerminal() bool {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.isTerminal
}
