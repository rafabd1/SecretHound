package output

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	SUCCESS
)

// LogMessage represents a log message in the queue
type LogMessage struct {
	Level   LogLevel
	Message string
	Time    time.Time
}

// Logger provides structured logging with queue management
type Logger struct {
	verbose     bool
	outputMu    sync.Mutex // Mutex for coordinating terminal output
	logQueue    chan LogMessage
	done        chan struct{}

	// Color functions
	debugColor   func(format string, a ...interface{}) string
	infoColor    func(format string, a ...interface{}) string
	warningColor func(format string, a ...interface{}) string
	errorColor   func(format string, a ...interface{}) string
	successColor func(format string, a ...interface{}) string
	timeColor    func(format string, a ...interface{}) string
	
	// Progress bar integration
	progressBar  *ProgressBar
	progressMu   sync.Mutex
}

// NewLogger creates a new logger
func NewLogger(verbose bool) *Logger {
	logger := &Logger{
		verbose:  verbose,
		logQueue: make(chan LogMessage, 100), // Buffer for 100 log messages
		done:     make(chan struct{}),

		// Initialize color functions
		debugColor:   color.New(color.FgHiBlack).SprintfFunc(),
		infoColor:    color.New(color.FgCyan).SprintfFunc(),
		warningColor: color.New(color.FgYellow).SprintfFunc(),
		errorColor:   color.New(color.FgRed, color.Bold).SprintfFunc(),
		successColor: color.New(color.FgGreen, color.Bold).SprintfFunc(),
		timeColor:    color.New(color.FgHiBlack).SprintfFunc(),
	}

	// Start log processor in background
	go logger.processLogs()

	return logger
}

// SetProgressBar configures the progress bar for the logger
func (l *Logger) SetProgressBar(pb *ProgressBar) {
	l.progressMu.Lock()
	defer l.progressMu.Unlock()
	l.progressBar = pb
}

// processLogs processes log messages from the queue
func (l *Logger) processLogs() {
	for {
		select {
		case <-l.done:
			return
		case msg := <-l.logQueue:
			// Lock output to prevent race with progress bar
			l.outputMu.Lock()
			l.writeLog(msg)
			l.outputMu.Unlock()
		}
	}
}

// writeLog writes a log message to the console
func (l *Logger) writeLog(msg LogMessage) {
    // Skip INFO, DEBUG and WARNING messages if not in verbose mode
    if !l.verbose && (msg.Level == INFO || msg.Level == DEBUG || msg.Level == WARNING) {
        return
    }

    // Acesso ao TerminalController para coordenação da saída
    tc := GetTerminalController()
    
    // Guarde uma referência ao ProgressBar para evitar lock durante a escrita
    l.progressMu.Lock()
    pb := l.progressBar
    l.progressMu.Unlock()
    
    // Pausa na renderização se existir uma barra de progresso
    if pb != nil {
        pb.PauseRender()
    }
    
    // Usar o controlador de terminal para coordenar a saída
    tc.CoordinateOutput(func() {
        // Format and print the log message
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
    
    // Se temos uma barra de progresso, restaure-a após o log
    if pb != nil {
        // Pequena pausa para garantir que o log seja visível
        time.Sleep(1 * time.Millisecond)
        pb.ResumeRender()
    }
}

// enqueueLog adds a log message to the queue
func (l *Logger) enqueueLog(level LogLevel, format string, args ...interface{}) {
	// Create log message
	msg := LogMessage{
		Level:   level,
		Message: fmt.Sprintf(format, args...),
		Time:    time.Now(),
	}

	// Non-blocking send to the log queue
	select {
	case l.logQueue <- msg:
		// Message sent successfully
	default:
		// Queue is full, write directly to avoid blocking
		l.outputMu.Lock()
		l.writeLog(msg)
		l.outputMu.Unlock()
	}
}

// Debug logs a debug message (only shown in verbose mode)
func (l *Logger) Debug(format string, args ...interface{}) {
	l.enqueueLog(DEBUG, format, args...)
}

// Info logs an informational message (only shown in verbose mode)
func (l *Logger) Info(format string, args ...interface{}) {
	l.enqueueLog(INFO, format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.enqueueLog(WARNING, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.enqueueLog(ERROR, format, args...)
}

// Success logs a success message
func (l *Logger) Success(format string, args ...interface{}) {
	l.enqueueLog(SUCCESS, format, args...)
}

// SecretFound logs a discovered secret
func (l *Logger) SecretFound(secretType, value, url string) {
	// Truncate value if it's too long
	truncatedValue := value
	if len(value) > 50 {
		truncatedValue = value[:47] + "..."
	}

	l.Success("Found %s: %s in %s", secretType, truncatedValue, url)
}

// Melhorar a implementação da função Flush para garantir que todas as mensagens de log sejam processadas

func (l *Logger) Flush() {
    // Implementação mais robusta para drenar a fila de log
    startTime := time.Now()
    maxWaitTime := 500 * time.Millisecond
    
    for len(l.logQueue) > 0 {
        // Verificar se excedeu o tempo máximo de espera
        if time.Since(startTime) > maxWaitTime {
            break
        }
        
        // Pausa breve para dar chance de processar
        time.Sleep(10 * time.Millisecond)
    }
    
    // Pausa final para garantir processamento de mensagens
    time.Sleep(50 * time.Millisecond)
    
    // Garantir que a barra de progresso seja finalizada corretamente
    l.progressMu.Lock()
    if l.progressBar != nil {
        l.progressBar.Stop()
        l.progressBar.Finalize()
        l.progressBar = nil
    }
    l.progressMu.Unlock()
}

// Close garante que todas as mensagens de log sejam processadas antes de encerrar
func (l *Logger) Close() {
    // Primeiro, drene a fila
    l.Flush()
    
    // Sinalize que nenhuma nova mensagem deve ser aceita
    close(l.done)
    
    // Libere recursos associados à barra de progresso
    l.progressMu.Lock()
    if l.progressBar != nil {
        l.progressBar.Stop()
        l.progressBar.Finalize()
        l.progressBar = nil
    }
    l.progressMu.Unlock()
}

// IsVerbose returns whether the logger is in verbose mode
func (l *Logger) IsVerbose() bool {
	return l.verbose
}

// SetVerbose sets the verbose mode
func (l *Logger) SetVerbose(verbose bool) {
	l.outputMu.Lock()
	defer l.outputMu.Unlock()
	l.verbose = verbose
}
