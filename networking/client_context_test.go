package networking

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetJSContentContextCancelsInFlightRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(5 * time.Second):
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	client := NewClient(5, 2)
	started := time.Now()

	_, err := client.GetJSContentContext(ctx, server.URL)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetJSContentContext() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("request cancellation took %s, want less than 1s", elapsed)
	}
}
