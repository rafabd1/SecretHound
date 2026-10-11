package cmd

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

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
