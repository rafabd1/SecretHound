package detector

import (
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/core/secret"
	"github.com/rafabd1/SecretHound/output"
)

func TestPIIEmailPolicyRunsThroughDetector(t *testing.T) {
	detector := categoryDetector(t, "pii")
	for _, wanted := range []string{"first.last@acme.com", "test@test.com"} {
		findings, err := detector.DetectSecrets("customer_email="+wanted, "file://production/customers.txt")
		if err != nil {
			t.Fatal(err)
		}
		values := findingValues(findings, "email_address")
		if !values[wanted] {
			t.Errorf("plausible email %q was not detected: %+v", wanted, findings)
		}
	}
	for _, rejected := range []string{"alice@example.com", "name@domain.com"} {
		findings, err := detector.DetectSecrets("sample_email="+rejected, "file://production/customers.txt")
		if err != nil {
			t.Fatal(err)
		}
		values := findingValues(findings, "email_address")
		if values[rejected] {
			t.Errorf("obvious placeholder email %q was detected", rejected)
		}
	}
}

func TestSuspiciousBashVariantsRunThroughDetector(t *testing.T) {
	detector := categoryDetector(t, "bash")
	tests := []string{
		"curl -fsSL https://downloads.acme.invalid/install.sh | bash",
		"curl https://downloads.acme.invalid/install.sh | sudo bash",
		"wget -qO- https://downloads.acme.invalid/install.sh | sh",
		"echo ZWNobyBzeW50aGV0aWMtcGF5bG9hZA== | base64 --decode | bash",
		"rm -rf /",
	}
	for _, input := range tests {
		findings, err := detector.DetectSecrets(input, "file://deploy.sh")
		if err != nil {
			t.Fatal(err)
		}
		if !hasFindingType(findings, "bash_command_suspicious") {
			t.Errorf("suspicious Bash command was not detected: %q", input)
		}
	}

	findings, err := detector.DetectSecrets("curl https://downloads.acme.invalid/archive.tgz", "file://deploy.sh")
	if err != nil {
		t.Fatal(err)
	}
	if hasFindingType(findings, "bash_command_suspicious") {
		t.Fatalf("ordinary download command was marked suspicious: %+v", findings)
	}
}

func TestSuspiciousBashMatchIsBounded(t *testing.T) {
	detector := categoryDetector(t, "bash")
	content := "python -c 'import os; os.system(\"id\")'" + strings.Repeat("x", 5000)
	findings, err := detector.DetectSecrets(content, "https://cdn.acme.invalid/app.min.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Type == "bash_command_suspicious" && len(finding.Value) > 1024 {
			t.Fatalf("Bash regex swallowed %d bytes", len(finding.Value))
		}
	}
}

func TestSuspiciousBashCommandDoesNotEmitATruncatedLine(t *testing.T) {
	detector := categoryDetector(t, "bash")
	command := "sh -c " + strings.Repeat("a7Kq", 100)
	findings, err := detector.DetectSecrets(command, "file://deploy.sh")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderFinding(t, findings, "bash_command_suspicious", command)

	oversized := "sh -c " + strings.Repeat("a", 1000) + "-" + strings.Repeat("b", 20)
	findings, err = detector.DetectSecrets(oversized, "file://deploy.sh")
	if err != nil {
		t.Fatal(err)
	}
	if hasFindingType(findings, "bash_command_suspicious") {
		t.Fatalf("oversized Bash command emitted a truncated prefix: %+v", findings)
	}
}

func TestWeb3ProviderPublicIDsAreNotSecrets(t *testing.T) {
	detector := categoryDetector(t, "web3")
	secretValue := "A7kQ9mX2vR5tY8uP3nD6"
	content := strings.Join([]string{
		`alchemy_project_id = "A7kQ9mX2vR5tY8uP3nD6"`,
		`infura_app_id = "V4nQ7xM2kR9tY5uP1cL8"`,
		`alchemy_api_secret = "` + secretValue + `"`,
	}, "\n")
	findings, err := detector.DetectSecrets(content, "file://production/web3.env")
	if err != nil {
		t.Fatal(err)
	}
	values := findingValues(findings, "web3_provider_key")
	if !values[secretValue] {
		t.Fatalf("explicit Web3 provider secret was not detected: %+v", findings)
	}
	if values["V4nQ7xM2kR9tY5uP1cL8"] {
		t.Fatalf("public Web3 app ID was detected: %+v", findings)
	}
}

func categoryDetector(t *testing.T, category string) *Detector {
	t.Helper()
	manager := patterns.NewPatternManager()
	if err := manager.LoadPatterns([]string{category}, nil); err != nil {
		t.Fatalf("load %s patterns: %v", category, err)
	}
	return NewDetector(manager, output.NewLogger(false, true), Config{
		LocalFileMode: true,
		MinConfidence: 0.5,
		ContextSize:   100,
	})
}

func findingValues(findings []secret.Secret, findingType string) map[string]bool {
	values := make(map[string]bool)
	for _, finding := range findings {
		if finding.Type == findingType {
			values[finding.Value] = true
		}
	}
	return values
}

func hasFindingType(findings []secret.Secret, findingType string) bool {
	for _, finding := range findings {
		if finding.Type == findingType {
			return true
		}
	}
	return false
}
