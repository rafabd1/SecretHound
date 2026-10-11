package output

import (
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
	if message.Level != LevelFinding || message.Risk != "low" || !message.Dim {
		t.Fatalf("likely false positive queued with level=%v risk=%q dim=%v", message.Level, message.Risk, message.Dim)
	}
	if !strings.HasSuffix(message.Message, likelyFalsePositiveSuffix) {
		t.Fatalf("missing likely false-positive suffix: %q", message.Message)
	}
}
