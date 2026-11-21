package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

func TestLikelyFalsePositiveUsesFaintStyleForEntireLine(t *testing.T) {
	previousNoColor := color.NoColor
	previousNoColorEnv, hadNoColorEnv := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	color.NoColor = false
	defer func() {
		color.NoColor = previousNoColor
		if hadNoColorEnv {
			_ = os.Setenv("NO_COLOR", previousNoColorEnv)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	}()

	logger := NewLogger(false, false)
	defer logger.Close()

	message := "Found llm_openai_api_key: sk-proj-example... in file:///repo/tests/provider_fixtures.json [LIKELY FALSE POSITIVE]"
	formatted := logger.formatLogLine(LogMessage{
		Level:   LevelFinding,
		Message: message,
		Time:    time.Date(2026, time.October, 10, 2, 1, 58, 0, time.UTC),
		Risk:    "low",
		Dim:     true,
	})
	expected := "\x1b[2m[02:01:58] [LOW] " + message + "\x1b[22m"
	if formatted != expected {
		t.Fatalf("likely false-positive line = %q, want %q", formatted, expected)
	}
	if strings.Contains(formatted, "\x1b[32") || strings.Contains(formatted, "\x1b[1m") {
		t.Fatalf("dimmed line retained foreground color or bold style: %q", formatted)
	}

	uncertain := logger.formatLogLine(LogMessage{
		Level:   LevelFinding,
		Message: "Found api_key: value [SEMANTIC UNCERTAIN]",
		Time:    time.Date(2026, time.October, 10, 2, 1, 59, 0, time.UTC),
		Risk:    "low",
	})
	if strings.Contains(uncertain, "\x1b[2m") {
		t.Fatalf("uncertain line was unexpectedly dimmed: %q", uncertain)
	}

	literalSuffix := logger.formatLogLine(LogMessage{
		Level:   LevelFinding,
		Message: "Found path_value: report [LIKELY FALSE POSITIVE]",
		Time:    time.Date(2026, time.October, 10, 2, 2, 0, 0, time.UTC),
		Risk:    "low",
	})
	if strings.Contains(literalSuffix, "\x1b[2m") {
		t.Fatalf("literal suffix without semantic status was dimmed: %q", literalSuffix)
	}
}

func TestLikelyFalsePositiveOverridesForcedInfoLogging(t *testing.T) {
	logger := &Logger{logQueue: make(chan LogMessage, 1)}
	logger.SecretFoundWithCountReview(
		"llm_openai_api_key",
		"sk-proj-example",
		"file:///repo/tests/provider_fixtures.json",
		1,
		"high",
		true,
		"likely_false_positive",
		"",
	)

	message := <-logger.logQueue
	if message.Level != LevelFinding || message.Risk != "low" || !message.Dim || !message.Result {
		t.Fatalf("likely false positive queued with level=%v risk=%q dim=%v result=%v", message.Level, message.Risk, message.Dim, message.Result)
	}
	if !strings.HasSuffix(message.Message, likelyFalsePositiveSuffix) {
		t.Fatalf("missing likely false-positive suffix: %q", message.Message)
	}
}

func TestFindingsUseStdoutAndDiagnosticsUseStderr(t *testing.T) {
	logger := NewLogger(false, false)
	defer logger.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	logger.resultWriter = &stdout
	logger.logWriter = &stderr

	logger.writeLog(LogMessage{
		Level:   LevelFinding,
		Message: "Found api_key: value... in file:///source.js [SEMANTIC UNCERTAIN]",
		Time:    time.Date(2026, time.November, 21, 19, 0, 0, 0, time.UTC),
		Risk:    "low",
		Result:  true,
	})
	logger.writeLog(LogMessage{
		Level:   LevelInfo,
		Message: "Scan completed",
		Time:    time.Date(2026, time.November, 21, 19, 0, 1, 0, time.UTC),
	})

	if !strings.Contains(stdout.String(), "SEMANTIC UNCERTAIN") {
		t.Fatalf("finding was not written to stdout: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "SEMANTIC UNCERTAIN") {
		t.Fatalf("finding leaked to stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Scan completed") {
		t.Fatalf("diagnostic was not written to stderr: %q", stderr.String())
	}
}

func TestForcedInfoFindingRemainsAResult(t *testing.T) {
	logger := &Logger{logQueue: make(chan LogMessage, 1)}
	logger.SecretFoundWithCountReview("url", "https://example.com", "file:///source.js", 1, "informative", true, "", "")
	message := <-logger.logQueue
	if message.Level != LevelInfo || !message.Result {
		t.Fatalf("forced-info finding queued with level=%v result=%v", message.Level, message.Result)
	}
}
