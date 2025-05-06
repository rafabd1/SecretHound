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
    renderPaused     bool
    outputControl    chan struct{}
}

func NewProgressBar(total int, width int) *ProgressBar {
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

func (pb *ProgressBar) Start() {
    pb.mu.Lock()
    if pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    pb.startTime = time.Now()
    pb.isActive = true
    pb.autoRefresh = pb.isTerminal
    pb.mu.Unlock()
    
    tc := GetTerminalController()
    tc.SetProgressBarActive(true)
    
    if pb.isTerminal {
        go pb.outputManager()
        pb.requestRender()

        go func() {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Fprintf(os.Stderr, "Recovered from panic in progress bar auto-refresh: %v\n", r)
                }
            }()
            
            ticker := time.NewTicker(pb.refresh)
            defer ticker.Stop()
            
            for {
                select {
                case <-pb.done:
                    return
                case <-ticker.C:
                    pb.mu.Lock()
                    isGloballyActive := pb.isActive
                    pb.mu.Unlock()
                    
                    if isGloballyActive {
                        pb.requestRender()
                    }
                }
            }
        }()
    }
}

/* 
   Manages serialization of terminal output to prevent rendering conflicts
*/
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
        case <-time.After(1 * time.Second):
            pb.mu.Lock()
            isActive := pb.isActive
            pb.mu.Unlock()
            
            if !isActive {
                return
            }
        }
    }
}

func (pb *ProgressBar) requestRender() {
    pb.mu.Lock()
    isActive := pb.isActive && !pb.renderPaused
    pb.mu.Unlock()
    
    if (isActive) {
        select {
        case pb.outputControl <- struct{}{}:
        default:
        }
    }
}

func (pb *ProgressBar) Stop() {
    pb.mu.Lock()
    
    if !pb.isActive {
        pb.mu.Unlock()
        return
    }
    
    pb.isActive = false
    pb.autoRefresh = false
    
    select {
    case <-pb.done:
    default:
        close(pb.done)
    }
    
    pb.mu.Unlock()
    
    tc := GetTerminalController()
    tc.SetProgressBarActive(false)
    
    time.Sleep(20 * time.Millisecond)
    
    if pb.isTerminal {
        pb.clearBar()
        fmt.Fprintln(pb.writer)
    }
}

func (pb *ProgressBar) Finalize() {
    pb.Stop()
    
    pb.mu.Lock()
    if pb.outputControl != nil {
        select {
        case <-pb.outputControl:
        default:
        }
    }
    pb.outputControl = nil
    pb.mu.Unlock()
    
    if pb.isTerminal {
        fmt.Fprint(pb.writer, "\033[2K\r")
        fmt.Fprintln(pb.writer)
    }
}

func (pb *ProgressBar) Update(current int) {
    pb.mu.Lock()
    pb.current = current
    shouldRender := !pb.autoRefresh && !pb.renderPaused
    pb.mu.Unlock()
    
    if shouldRender {
        pb.requestRender()
    }
}

func (pb *ProgressBar) SetPrefix(prefix string) {
    pb.mu.Lock()
    pb.prefix = prefix
    pb.mu.Unlock()
}

func (pb *ProgressBar) SetSuffix(suffix string) {
    pb.mu.Lock()
    pb.suffix = suffix
    pb.mu.Unlock()
}

func (pb *ProgressBar) PauseRender() {
    pb.mu.Lock()
    pb.renderPaused = true
    pb.mu.Unlock()
}

func (pb *ProgressBar) ResumeRender() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused
    pb.renderPaused = false
    pb.mu.Unlock()
    
    if wasRenderPaused {
        pb.requestRender()
    }
}

func (pb *ProgressBar) actualRender() {
    pb.mu.Lock()
    
    if !pb.isActive || !pb.isTerminal {
        pb.mu.Unlock()
        return
    }
    
    pb.spinner = (pb.spinner + 1) % len(pb.spinnerChars)
    
    percent := float64(pb.current) / float64(pb.total) * 100
    if pb.total == 0 {
        percent = 0
    }
    
    elapsed := time.Since(pb.startTime)
    
    var eta time.Duration
    var etaStr string
    if pb.current > 0 && pb.current < pb.total {
        eta = time.Duration(float64(elapsed) * float64(pb.total-pb.current) / float64(pb.current))
        etaStr = formatDuration(eta)
    } else {
        etaStr = "N/A"
    }
    
    completed := int(float64(pb.width) * float64(pb.current) / float64(pb.total))
    if completed > pb.width {
        completed = pb.width
    }
    
    bar := strings.Repeat("█", completed) + strings.Repeat("░", pb.width-completed)
    
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
    
    tc := GetTerminalController()
    tc.BeginOutput()
    fmt.Fprint(pb.writer, "\033[2K\r"+status)
    tc.EndOutput()
}

/* 
   Clears the current line to make space for logging output 
*/
func (pb *ProgressBar) MoveForLog() {
    pb.mu.Lock()
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    
    pb.renderPaused = true
    
    select {
    case <-pb.outputControl:
    default:
    }
    
    pb.mu.Unlock()
    
    if isActiveAndTerminal {
        fmt.Fprint(pb.writer, "\033[2K\r")
        time.Sleep(1 * time.Millisecond)
    }
}

func (pb *ProgressBar) ShowAfterLog() {
    pb.mu.Lock()
    wasRenderPaused := pb.renderPaused
    isActiveAndTerminal := pb.isActive && pb.isTerminal
    pb.renderPaused = false
    pb.mu.Unlock()
    
    if wasRenderPaused && isActiveAndTerminal {
        time.Sleep(1 * time.Millisecond)
        pb.actualRender()
    }
}

func (pb *ProgressBar) clearBar() {
    if pb.isTerminal {
        fmt.Fprint(pb.writer, "\033[2K\r")
    }
}

/* 
   Formats a time duration into a human-readable string
*/
func formatDuration(d time.Duration) string {
    if d.Minutes() < 1 {
        return fmt.Sprintf("%.1fs", d.Seconds())
    }
    
    if d.Hours() < 1 {
        minutes := int(d.Minutes())
        seconds := int(d.Seconds()) % 60
        return fmt.Sprintf("%dm%02ds", minutes, seconds)
    }
    
    hours := int(d.Hours())
    minutes := int(d.Minutes()) % 60
    seconds := int(d.Seconds()) % 60
    return fmt.Sprintf("%dh%02dm%02ds", hours, minutes, seconds)
}
