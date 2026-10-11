package core

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
)

func TestRegexManagerUsesEachMatchOffsetForRepeatedValues(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.AddPattern("repeated_token", `token\s*=\s*"(repeat_A1B2C3D4E5F6)"`, "Repeated token"); err != nil {
		t.Fatal(err)
	}
	regexManager := NewRegexManager()
	regexManager.SetPatternManager(manager)
	content := "example token = \"repeat_A1B2C3D4E5F6\"\n" + strings.Repeat("x", 240) + "\nproduction token = \"repeat_A1B2C3D4E5F6\""

	findings, err := regexManager.FindSecrets(content, "https://example.invalid/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, expected only the production occurrence: %+v", len(findings), findings)
	}
	if findings[0].Line != 3 {
		t.Fatalf("production occurrence has wrong line: %d", findings[0].Line)
	}
	if strings.Contains(findings[0].Context, "example") {
		t.Fatalf("production occurrence inherited example context: %#v", findings[0].Context)
	}
	if !strings.Contains(findings[0].Context, "production") {
		t.Fatalf("production context is wrong: %#v", findings[0].Context)
	}
}

func TestRegexManagerUsesSameDetectionPathForLocalAndRemoteContent(t *testing.T) {
	manager := patterns.NewPatternManager()
	if err := manager.AddPattern("shared_token", `token\s*=\s*"(shared_A1B2C3D4E5F6)"`, "Shared token"); err != nil {
		t.Fatal(err)
	}
	regexManager := NewRegexManager()
	regexManager.SetPatternManager(manager)
	content := "header\nproduction token = \"shared_A1B2C3D4E5F6\""

	remote, err := regexManager.FindSecrets(content, "https://example.invalid/config.js")
	if err != nil {
		t.Fatal(err)
	}
	local, err := regexManager.FindSecrets(content, "file:///config.js")
	if err != nil {
		t.Fatal(err)
	}

	if len(remote) != 1 || len(local) != 1 {
		t.Fatalf("local/remote detection diverged: remote=%+v local=%+v", remote, local)
	}
	if remote[0].Type != local[0].Type || remote[0].Value != local[0].Value || remote[0].Line != local[0].Line {
		t.Fatalf("local/remote findings differ: remote=%+v local=%+v", remote[0], local[0])
	}
}
