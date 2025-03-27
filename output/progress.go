package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/utils"
)

// ProgressBar represents a thread-safe progress bar
type ProgressBar struct {
    total            int
    current          int
    width            int
    refresh          time.Duration
    startTime        time.Time
    mu               sync.Mutex
    done             chan struct{}
    writer           io.Writer
    lastPrintedChars int
    autoRefresh      bool
    isActive         bool
    spinner          int
    spinnerChars     []string
    prefix           string
    suffix           string
    isTerminal       bool
    // Flag to control rendering during log operations
    renderPaused     bool
    // Output control channel
    outputControl    chan struct{}
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, width int) *ProgressBar {
    // Check if we're running in a terminal
    isTTY := utils.IsTerminal(os.Stderr.Fd())
    
    return &ProgressBar{
        total:         total,
        current:       0,
        width:         width,
        refresh:       100 * time.Millisecond,
        startTime:     time.Now(),
        done:          make(chan struct{}),
        writer:        os.Stderr,
        isActive:      false,
        spinnerChars:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
        prefix:        "",
        suffix:        "",
        isTerminal:    isTTY,
        renderPaused:  false,
        outputControl: make(chan struct{}, 1),
    }
}

// Start starts the progress bar with auto-refresh
func (pb *ProgressBar) Start() {
    pb.mu.Lock()
    if pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    pb.startTime = time.Now()
    pb.isActive = true
    pb.autoRefresh = pb.isTerminal // Only auto-refresh in terminal environments
    pb.mu.Unlock()
    
    // Notify the terminal controller that a progress bar is active
    tc := GetTerminalController()
    tc.SetProgressBarActive(true)
    
    // Initial render if in a terminal
    if pb.isTerminal {
        // Start output control manager - this serializes all terminal output
        go pb.outputManager()

        // Force an initial render to ensure the bar is visible
        pb.requestRender()

        // Start auto-refresh goroutine
        go func() {
            defer func() {
                // Recovery from panic
                if r := recover(); r != nil {
                    fmt.Fprintf(os.Stderr, "Recovered from panic in progress bar: %v\n", r)
                }
            }()
            
            for {
                select {
                case <-pb.done:
                    return
                case <-time.After(pb.refresh):
                    pb.mu.Lock()
                    isActive := pb.isActive && !pb.renderPaused
                    pb.mu.Unlock()
                    
                    if !isActive {
                        return
                    }
                    
                    pb.requestRender()
                }
            }
        }()
    }
}

// outputManager handles serialization of terminal output
func (pb *ProgressBar) outputManager() {
    for {
        select {
        case <-pb.done:
            return
        case <-pb.outputControl:
            pb.mu.Lock()
            shouldRender := pb.isActive && !pb.renderPaused
            pb.mu.Unlock()
            
            if shouldRender {
                pb.actualRender()
            }
        case <-time.After(1 * time.Second): // Timeout to prevent blocking
            pb.mu.Lock()
            isActive := pb.isActive
            pb.mu.Unlock()
            
            if !isActive {
                return
            }
        }
    }
}

// requestRender triggers a render operation via the control channel
func (pb *ProgressBar) requestRender() {
    pb.mu.Lock()
    isActive := pb.isActive && !pb.renderPaused
    pb.mu.Unlock()
    
    if (isActive) {
        // Non-blocking send
        select {
        case pb.outputControl <- struct{}{}:
            // Request sent
        default:
            // Channel full, skip this update
        }
    }
}

// Stop stops the progress bar
func (pb *ProgressBar) Stop() {
    pb.mu.Lock()
    
    if !pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    // Stop the auto-refresh goroutine
    pb.isActive = false
    pb.autoRefresh = false
    
    // Close the done channel to signal goroutines to stop
    select {
    case <-pb.done:
        // Already closed
    default:
        close(pb.done)
    }
    
    pb.mu.Unlock()
    
    // Notify the terminal controller that no progress bar is active
    tc := GetTerminalController()
    tc.SetProgressBarActive(false)
    
    // Wait for the output manager to finish
    time.Sleep(20 * time.Millisecond)
    
    // Clear the progress bar
    if pb.isTerminal {
        pb.clearBar()
        fmt.Fprintln(pb.writer)
    }
}

// Finalize finalizes the progress bar and cleans up resources
func (pb *ProgressBar) Finalize() {
    pb.Stop()
    
    pb.mu.Lock()
    if pb.outputControl != nil {
        // Clear the channel explicitly
        select {
        case <-pb.outputControl:
            // Consumed one item
        default:
            // Channel was already empty
        }
    }
    pb.outputControl = nil // Set to nil to release resources
    pb.mu.Unlock()
    
    // Final cleanup
    if pb.isTerminal {
        fmt.Fprint(pb.writer, "\033[2K\r")
        fmt.Fprintln(pb.writer)
    }
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
    pb.mu.Lock()
    pb.current = current
    shouldRender := !pb.autoRefresh && !pb.renderPaused
    pb.mu.Unlock()
    
    if shouldRender {
        pb.requestRender()
    }
}

// SetPrefix sets the prefix for the progress bar
func (pb *ProgressBar) SetPrefix(prefix string) {
    pb.mu.Lock()
    pb.prefix = prefix
    pb.mu.Unlock()
}

// SetSuffix sets the suffix for the progress bar
func (pb *ProgressBar) SetSuffix(suffix string) {
    pb.mu.Lock()
    pb.suffix = suffix
    pb.mu.Unlock()
}

// PauseRender temporarily pauses rendering during log operations
func (pb *ProgressBar) PauseRender() {
    pb.mu.Lock()
    pb.renderPaused = true
    pb.mu.Unlock()
}

// ResumeRender resumes rendering after log operations
func (pb *ProgressBar) ResumeRender() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused
    pb.renderPaused = false
    pb.mu.Unlock()
    
    if wasRenderPaused {
        pb.requestRender()
    }
}

// The actual rendering function - called only by outputManager
func (pb *ProgressBar) actualRender() {
    pb.mu.Lock()
    
    if !pb.isActive || !pb.isTerminal {
        pb.mu.Unlock()
        return
    }
    
    // Update spinner
    pb.spinner = (pb.spinner + 1) % len(pb.spinnerChars)
    
    // Calculate percentage
    percent := float64(pb.current) / float64(pb.total) * 100
    if pb.total == 0 {
        percent = 0
    }
    
    // Calculate elapsed time
    elapsed := time.Since(pb.startTime)
    
    // Calculate ETA
    var eta time.Duration
    var etaStr string
    if pb.current > 0 && pb.current < pb.total {
        eta = time.Duration(float64(elapsed) * float64(pb.total-pb.current) / float64(pb.current))
        etaStr = formatDuration(eta)
    } else {
        etaStr = "N/A"
    }
    
    // Generate progress bar
    completed := int(float64(pb.width) * float64(pb.current) / float64(pb.total))
    if completed > pb.width {
        completed = pb.width
    }
    
    bar := strings.Repeat("█", completed) + strings.Repeat("░", pb.width-completed)
    
    // Format progress status
    status := fmt.Sprintf("%s%s [%s] %d/%d (%0.2f%%) | %s ETA: %s %s",
        pb.prefix,
        pb.spinnerChars[pb.spinner],
        bar,
        pb.current, pb.total,
        percent,
        formatDuration(elapsed),
        etaStr,
        pb.suffix,
    )
    
    pb.lastPrintedChars = len(status)
    pb.mu.Unlock()
    
    // Output the status string with terminal controller coordination
    tc := GetTerminalController()
    tc.BeginOutput()
    fmt.Fprint(pb.writer, "\033[2K\r"+status)
    tc.EndOutput()
}

// MoveForLog prepares for log output by clearing the current line
func (pb *ProgressBar) MoveForLog() {
    pb.mu.Lock()
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    
    // Pause rendering during log operation
    pb.renderPaused = true
    
    // Important: drain any pending renders to prevent race conditions
    select {
    case <-pb.outputControl:
        // Drained one request
    default:
        // No pending requests
    }
    
    pb.mu.Unlock()
    
    if isActiveAndTerminal {
        // Clear the line completely using ANSI escape codes
        fmt.Fprint(pb.writer, "\033[2K\r")
        
        // Add a small delay to ensure terminal processes the clear command
        time.Sleep(1 * time.Millisecond)
    }
}

// ShowAfterLog restores the progress bar after a log message
func (pb *ProgressBar) ShowAfterLog() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    pb.renderPaused = false
    pb.mu.Unlock()
    
    if wasRenderPaused && isActiveAndTerminal {
        // Force an immediate render with a small delay to ensure logs are displayed first
        time.Sleep(1 * time.Millisecond)
        pb.actualRender()
    }
}

// clearBar clears the current progress bar from the terminal
func (pb *ProgressBar) clearBar() {
    if pb.isTerminal {
        fmt.Fprint(pb.writer, "\033[2K\r")
    }
}

// formatDuration formats a duration to a human-readable string
func formatDuration(d time.Duration) string {
    // If less than a minute, show seconds
    if d.Minutes() < 1 {
        return fmt.Sprintf("%.1fs", d.Seconds())
    }
    
    // If less than an hour, show minutes:seconds
    if d.Hours() < 1 {
        minutes := int(d.Minutes())
        seconds := int(d.Seconds()) % 60
        return fmt.Sprintf("%dm%02ds", minutes, seconds)
    }
    
    // Show hours:minutes:seconds
    hours := int(d.Hours())
    minutes := int(d.Minutes()) % 60
    seconds := int(d.Seconds()) % 60
    return fmt.Sprintf("%dh%02dm%02ds", hours, minutes, seconds)
}