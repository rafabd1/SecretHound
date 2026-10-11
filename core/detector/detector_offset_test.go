package detector

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/output"
)

func TestDetectorUsesEachMatchOffsetForRepeatedValues(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.AddPattern("repeated_token", `token\s*=\s*"(repeat_A1B2C3D4E5F6)"`, "Repeated token"); err != nil {
		t.Fatal(err)
	}
	detector := NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   24,
	})
	content := "example token = \"repeat_A1B2C3D4E5F6\"\n" + strings.Repeat("x", 80) + "\nproduction token = \"repeat_A1B2C3D4E5F6\""

	findings, err := detector.DetectSecrets(content, "file:///config.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, expected 2: %+v", len(findings), findings)
	}
	for _, finding := range findings {
		if !finding.HasContextOffset || finding.ContextOffset < 0 ||
			finding.ContextOffset+len(finding.Value) > len(finding.Context) ||
			finding.Context[finding.ContextOffset:finding.ContextOffset+len(finding.Value)] != finding.Value {
			t.Fatalf("finding context offset does not identify its value: %+v", finding)
		}
	}
	if findings[0].Line != 1 || findings[1].Line != 3 {
		t.Fatalf("wrong lines for repeated value: %d, %d", findings[0].Line, findings[1].Line)
	}
	if !strings.Contains(findings[0].Context, "example") || strings.Contains(findings[1].Context, "example") {
		t.Fatalf("contexts did not follow match offsets: %#v / %#v", findings[0].Context, findings[1].Context)
	}
	if !strings.Contains(findings[1].Context, "production") {
		t.Fatalf("second context is wrong: %#v", findings[1].Context)
	}
}
