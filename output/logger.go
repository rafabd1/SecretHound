package output

import (
    "fmt"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/rafabd1/SecretHound/utils"
)

type LogLevel int

const (
    DEBUG LogLevel = iota
    INFO
    WARNING
    ERROR
    SUCCESS
)

type LogMessage struct {
    Level     LogLevel
    Message   string
    Time      time.Time
    Critical  bool
}

type Logger struct {
    verbose     bool
    outputMu    sync.Mutex
    logQueue    chan LogMessage
    done        chan struct{}

    debugColor   func(format string, a ...interface{}) string
    infoColor    func(format string, a ...interface{}) string
    warningColor func(format string, a ...interface{}) string
    errorColor   func(format string, a ...interface{}) string
    successColor func(format string, a ...interface{}) string
    timeColor    func(format string, a ...interface{}) string
    
    progressBar  *ProgressBar
    progressMu   sync.Mutex

    loggedSecrets map[string]bool
    secretsMutex  sync.Mutex
}

func NewLogger(verbose bool) *Logger {
    logger := &Logger{
        verbose:  verbose,
        logQueue: make(chan LogMessage, 100),
        done:     make(chan struct{}),

        timeColor:    color.New(color.FgHiBlack).SprintfFunc(),
        debugColor:   color.New(color.FgHiBlack).SprintfFunc(),
        infoColor:    color.New(color.FgCyan).SprintfFunc(),
        warningColor: color.New(color.FgYellow).SprintfFunc(),
        errorColor:   color.New(color.FgRed, color.Bold).SprintfFunc(),
        successColor: color.New(color.FgGreen, color.Bold).SprintfFunc(),

        loggedSecrets: make(map[string]bool),
    }

    go logger.processLogs()

    return logger
}

func (l *Logger) SetProgressBar(pb *ProgressBar) {
    l.progressMu.Lock()
    defer l.progressMu.Unlock()
    l.progressBar = pb
}

/* 
   Processes log messages from the queue in background 
*/
func (l *Logger) processLogs() {
    for {
        select {
        case <-l.done:
            return
        case msg := <-l.logQueue:
            l.outputMu.Lock()
            l.writeLog(msg)
            l.outputMu.Unlock()
        }
    }
}

func (l *Logger) writeLog(msg LogMessage) {
    if !l.verbose && msg.Level == DEBUG {
        return
    }
    
    if !l.verbose && (msg.Level == INFO || msg.Level == WARNING) {
        return
    }
    
    if !l.verbose && msg.Level == ERROR && !msg.Critical {
        return
    }
    
    tc := GetTerminalController()
    
    l.progressMu.Lock()
    pb := l.progressBar
    l.progressMu.Unlock()
    
    if pb != nil {
        pb.PauseRender()
    }
    
    tc.CoordinateOutput(func() {
        timestamp := l.timeColor("[%s]", msg.Time.Format("15:04:05"))
        var prefix string
        var formatted string

        switch msg.Level {
        case DEBUG:
            prefix = l.debugColor("[DEBUG]")
            formatted = l.debugColor("%s", msg.Message)
        case INFO:
            prefix = l.infoColor("[INFO]")
            formatted = msg.Message
        case WARNING:
            prefix = l.warningColor("[WARNING]")
            formatted = l.warningColor("%s", msg.Message)
        case ERROR:
            prefix = l.errorColor("[ERROR]")
            formatted = l.errorColor("%s", msg.Message)
        case SUCCESS:
            prefix = l.successColor("[SUCCESS]")
            formatted = l.successColor("%s", msg.Message)
        }

        fmt.Fprintf(os.Stderr, "%s %s %s\n", timestamp, prefix, formatted)
    })
    
    if pb != nil {
        time.Sleep(1 * time.Millisecond)
        pb.ResumeRender()
    }
}

func (l *Logger) enqueueLog(level LogLevel, format string, args ...interface{}) {
    msg := LogMessage{
        Level:   level,
        Message: fmt.Sprintf(format, args...),
        Time:    time.Now(),
        Critical: isCriticalMessage(level, format),
    }

    select {
    case l.logQueue <- msg:
    default:
        l.outputMu.Lock()
        l.writeLog(msg)
        l.outputMu.Unlock()
    }
}

/* 
   Determines if a message should be shown regardless of verbose mode 
*/
func isCriticalMessage(level LogLevel, message string) bool {
    if level == SUCCESS {
        return true
    }
    
    if level == ERROR {
        criticalPatterns := []string{
            "failed to create output file",
            "no valid input sources found",
            "failed to access input file",
            "failed to load regex patterns",
            "timeout exceeded",
            "fatal error",
        }
        
        for _, pattern := range criticalPatterns {
            if strings.Contains(strings.ToLower(message), pattern) {
                return true
            }
        }
    }
    
    return false
}

func (l *Logger) Debug(format string, args ...interface{}) {
    l.enqueueLog(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
    l.enqueueLog(INFO, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
    l.enqueueLog(WARNING, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
    l.enqueueLog(ERROR, format, args...)
}

func (l *Logger) Success(format string, args ...interface{}) {
    l.enqueueLog(SUCCESS, format, args...)
}

/* 
   Logs a discovered secret while avoiding duplicates 
*/
func (l *Logger) SecretFound(secretType string, secretValue string, url string) {
    key := fmt.Sprintf("%s:%s:%s", url, secretType, secretValue)
    
    l.secretsMutex.Lock()
    
    if _, exists := l.loggedSecrets[key]; exists {
        l.secretsMutex.Unlock()
        return
    }
    
    l.loggedSecrets[key] = true
    l.secretsMutex.Unlock()
    
    secretPart := utils.TruncateString(secretValue, 35)
    
    l.Success("Found %s: %s... in %s", secretType, secretPart, url)
    
    time.Sleep(5 * time.Millisecond)
}

/* 
   Flushes all queued log messages and ensures they are processed 
*/
func (l *Logger) Flush() {
    startTime := time.Now()
    maxWaitTime := 1000 * time.Millisecond
    
    for len(l.logQueue) > 0 {
        if time.Since(startTime) > maxWaitTime {
            break
        }
    
        time.Sleep(20 * time.Millisecond)
    }
    
    time.Sleep(200 * time.Millisecond)
    
    l.progressMu.Lock()
    if l.progressBar != nil {
        l.progressBar.Stop()
        l.progressBar.Finalize()
        l.progressBar = nil
    }
    l.progressMu.Unlock()
    
    tc := GetTerminalController()
    if tc.IsTerminal() {
        tc.ClearLine()
    }
}

func (l *Logger) Close() {
    l.Flush()
    
    close(l.done)
    
    l.progressMu.Lock()
    if l.progressBar != nil {
        l.progressBar.Stop()
        l.progressBar.Finalize()
        l.progressBar = nil
    }
    l.progressMu.Unlock()
}

/* 
   Completely resets the logger's internal state 
*/
func (l *Logger) ResetState() {
    l.outputMu.Lock()
    defer l.outputMu.Unlock()
    
    l.secretsMutex.Lock()
    defer l.secretsMutex.Unlock()
    
    l.loggedSecrets = make(map[string]bool)
    
    drainLoop:
        for len(l.logQueue) > 0 {
            select {
            case <-l.logQueue:
            default:
                break drainLoop
            }
        }
    
    l.progressMu.Lock()
    l.progressBar = nil
    l.progressMu.Unlock()
}

func (l *Logger) IsVerbose() bool {
    return l.verbose
}

func (l *Logger) SetVerbose(verbose bool) {
    l.outputMu.Lock()
    defer l.outputMu.Unlock()
    l.verbose = verbose
}
