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
    // Levels ordered by verbosity (lower value = more verbose)
    LevelDebug LogLevel = iota
    LevelInfo
    LevelSuccess // Success messages are important, shown unless silent
    LevelWarning
    LevelError
    LevelFatal // Not really a level, but used for critical errors
    LevelSilent // A level higher than Error to suppress almost everything
)

type LogMessage struct {
    Level     LogLevel
    Message   string
    Time      time.Time
    Critical  bool // Keep critical for very specific errors if needed
}

type Logger struct {
    minLevel    LogLevel // Use a minimum level instead of just verbose/silent bools
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

// NewLogger now accepts verbose and silent flags to determine the minimum log level
func NewLogger(verbose, silent bool) *Logger {
	minLogLevel := LevelInfo // Default level back to INFO
	if verbose {
		minLogLevel = LevelDebug // Verbose: Show everything
	}
	if silent {
		minLogLevel = LevelSuccess // Silent: Filtered further in writeLog
	}

	logger := &Logger{
		minLevel: minLogLevel,
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
	// Determine the current operational mode based on minLevel
	isSilent := l.minLevel == LevelSuccess
	// isVerbose := l.minLevel == LevelDebug // Removed as it wasn't used for filtering
	isDefault := l.minLevel == LevelInfo // Assumes default level is INFO

	// 1. Filter based on Silent mode
	if isSilent {
		if msg.Level != LevelSuccess {
			return // Only SUCCESS messages allowed in silent mode
		}
	// 2. Filter based on Default mode
	} else if isDefault {
		if msg.Level != LevelInfo && msg.Level != LevelSuccess {
			return // Only INFO and SUCCESS messages allowed in default mode
		}
	// 3. Verbose mode implicitly allows all levels to pass this point
	}

	// --- Proceed with printing if the message wasn't filtered out by mode logic ---
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
		case LevelDebug:
			prefix = l.debugColor("[DEBUG]")
			formatted = l.debugColor("%s", msg.Message)
		case LevelInfo:
			prefix = l.infoColor("[INFO]")
			formatted = msg.Message
		case LevelWarning:
			prefix = l.warningColor("[WARNING]")
			formatted = l.warningColor("%s", msg.Message)
		case LevelError:
			prefix = l.errorColor("[ERROR]")
			formatted = l.errorColor("%s", msg.Message)
		case LevelSuccess:
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
        Critical: isCriticalMessage(level, format), // Determine criticality
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
   Determines if a message should bypass normal level filtering
   (Used primarily for critical ERROR messages that should show even if default level is higher)
   NOTE: This is less relevant now with the stricter silent mode logic in writeLog.
*/
func isCriticalMessage(level LogLevel, message string) bool {
	// SUCCESS messages are no longer automatically critical
	if level == LevelError {
		// Define patterns for errors that MUST be shown even if minLevel is Warning/Success
		criticalPatterns := []string{
			"failed to create output file",
			"no valid input sources found",
			"failed to access input file",
			"error loading patterns:",
			"fatal error",
		}

		msgLower := strings.ToLower(message)
		for _, pattern := range criticalPatterns {
			if strings.Contains(msgLower, pattern) {
				return true
			}
		}
	}
	return false
}

func (l *Logger) Debug(format string, args ...interface{}) {
    l.enqueueLog(LevelDebug, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
    l.enqueueLog(LevelInfo, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
    l.enqueueLog(LevelWarning, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
    l.enqueueLog(LevelError, format, args...)
}

func (l *Logger) Success(format string, args ...interface{}) {
    l.enqueueLog(LevelSuccess, format, args...)
}

// Fatal logs directly to stderr and exits, bypassing queue and levels
func (l *Logger) Fatal(format string, args ...interface{}) {
    l.outputMu.Lock() // Ensure atomicity with other logs
    defer l.outputMu.Unlock()
    
    tc := GetTerminalController()
    pb := l.progressBar
    if pb != nil {
        pb.PauseRender()
    }

    timestamp := l.timeColor("[%s]", time.Now().Format("15:04:05"))
    prefix := l.errorColor("[FATAL]")
    formatted := l.errorColor(format, args...)
    
    tc.CoordinateOutput(func() {
        fmt.Fprintf(os.Stderr, "%s %s %s\n", timestamp, prefix, formatted)
    })
    
    l.Close() // Attempt to close gracefully
    os.Exit(1)
}

/* 
   Logs a discovered secret while avoiding duplicates 
*/
func (l *Logger) SecretFound(secretType string, secretValue string, url string) {
    // This message uses Success level, it will be shown unless silent mode
    // is configured to suppress LevelSuccess.
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

// IsSilent returns true if the logger is configured to suppress most output
func (l *Logger) IsSilent() bool {
    return l.minLevel >= LevelSuccess // Or adjust based on exact silent definition
}

// IsVerbose remains useful
func (l *Logger) IsVerbose() bool {
    return l.minLevel == LevelDebug
}
