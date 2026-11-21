package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rafabd1/SecretHound/core/patterns"
	"github.com/rafabd1/SecretHound/networking"
	"github.com/rafabd1/SecretHound/output"
	"github.com/spf13/viper"
)

func TestCollectInputSourcesPreservesHTTPURL(t *testing.T) {
	logger := output.NewLogger(false, true)
	t.Cleanup(logger.Close)
	url := "https://example.com/assets/app.js?chunk=one/two"

	inputs, err := collectInputSources("", []string{url}, logger, 0)
	if err != nil {
		t.Fatalf("collectInputSources() error = %v", err)
	}
	if !reflect.DeepEqual(inputs, []string{url}) {
		t.Fatalf("collectInputSources() = %q, want unchanged URL %q", inputs, url)
	}
}

func TestMaxDurationFlagIsRegisteredAndDisabledByDefault(t *testing.T) {
	flag := rootCmd.Flags().Lookup("max-duration")
	if flag == nil {
		t.Fatal("max-duration flag is not registered")
	}
	if flag.DefValue != "0s" {
		t.Fatalf("max-duration default = %q, want 0s", flag.DefValue)
	}
}

func TestPrintPatternListExplainsDefinitionStates(t *testing.T) {
	manager := patterns.NewPatternManager()
	stats := manager.GetLoadStats()
	var output bytes.Buffer

	printPatternList(&output, manager)
	text := output.String()
	listedDefinitions := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "  - ") {
			listedDefinitions++
		}
	}
	if listedDefinitions != stats.TotalDefinitions {
		t.Fatalf("listed %d definitions, want %d", listedDefinitions, stats.TotalDefinitions)
	}
	for _, expected := range []string{
		fmt.Sprintf("Definitions: %d total", stats.TotalDefinitions),
		fmt.Sprintf("Active by default: %d", stats.Loaded),
		"[active",
		"[opt-in",
		"active = loaded by default",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("pattern list missing %q", expected)
		}
	}
}

func TestListPatternsWritesOnlyToStdout(t *testing.T) {
	stdout, stderr, err := runCLIHelper("--list-patterns")
	if err != nil {
		t.Fatalf("--list-patterns failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "Pattern Definitions") {
		t.Fatalf("stdout missing pattern list: %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("successful pattern listing wrote to stderr: %q", stderr)
	}
	if strings.Contains(stdout, "Secrets Finder") {
		t.Fatalf("pattern listing included the interactive banner")
	}
}

func TestNoProgressRoutesFindingsWithoutCursorControls(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.env")
	if err := os.WriteFile(source, []byte("GOOGLE_API_KEY=AIzaSyA7mQ9xV2nR5tY8uP3kL6cB1hF4jW0zE7Q\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runCLIHelper(source, "--no-progress")
	if err != nil {
		t.Fatalf("scan failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "Found google_api_key") {
		t.Fatalf("stdout missing finding: %q", stdout)
	}
	if strings.Contains(stderr, "Found google_api_key") {
		t.Fatalf("finding leaked to stderr: %q", stderr)
	}
	if strings.Contains(stderr, "\x1b[2K") {
		t.Fatalf("--no-progress emitted a cursor-control sequence: %q", stderr)
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("SECRETHOUND_CLI_HELPER") != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		os.Exit(2)
	}
	rootCmd.SetArgs(os.Args[separator+1:])
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runCLIHelper(arguments ...string) (string, string, error) {
	commandArguments := []string{"-test.run=^TestCLIHelperProcess$", "--"}
	commandArguments = append(commandArguments, arguments...)
	command := exec.Command(os.Args[0], commandArguments...)
	command.Env = append(os.Environ(), "SECRETHOUND_CLI_HELPER=1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func TestApplyConfiguredRequestHeadersUsesBoundHeadersKey(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received <- request.Header.Get("X-SecretHound-Test")
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	config := viper.New()
	config.Set("headers", []string{"X-SecretHound-Test: configured"})
	config.Set("header", []string{"X-SecretHound-Test: wrong-key"})
	client := networking.NewClient(2, 0)
	logger := output.NewLogger(false, true)
	t.Cleanup(logger.Close)

	applyConfiguredRequestHeaders(config, client, logger)
	if _, err := client.GetJSContent(server.URL); err != nil {
		t.Fatalf("GetJSContent() error = %v", err)
	}
	if got := <-received; got != "configured" {
		t.Fatalf("request header = %q, want %q", got, "configured")
	}
}
