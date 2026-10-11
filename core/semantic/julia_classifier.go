package semantic

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed julia_worker.py
var juliaWorkerScript string

type JuliaConfig struct {
	PythonExecutable  string
	ModelPath         string
	Device            string
	MaxLength         int
	HeadLength        int
	FPThreshold       float64
	DecisionThreshold float64
	StartupTimeout    time.Duration
}

type workerRequest struct {
	Type       string      `json:"type"`
	ID         uint64      `json:"id,omitempty"`
	Candidates []Candidate `json:"candidates,omitempty"`
}

type workerResponse struct {
	Type    string       `json:"type"`
	ID      uint64       `json:"id,omitempty"`
	Results []Prediction `json:"results,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type JuliaClassifier struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *boundedBuffer

	mu       sync.Mutex
	closed   bool
	broken   error
	request  atomic.Uint64
	waitOnce sync.Once
	waitErr  error
}

func NewJuliaClassifier(config JuliaConfig) (*JuliaClassifier, error) {
	if strings.TrimSpace(config.ModelPath) == "" {
		return nil, errors.New("semantic model path is required")
	}
	if config.PythonExecutable == "" {
		config.PythonExecutable = "python"
	}
	if config.Device == "" {
		config.Device = "cpu"
	}
	if config.MaxLength <= 0 {
		config.MaxLength = 8192
	}
	if config.HeadLength <= 0 {
		config.HeadLength = 512
	}
	if config.FPThreshold <= 0 || config.FPThreshold > 1 {
		config.FPThreshold = 0.80
	}
	if config.DecisionThreshold <= 0 || config.DecisionThreshold > 1 {
		config.DecisionThreshold = 0.60
	}
	if config.StartupTimeout <= 0 {
		config.StartupTimeout = 2 * time.Minute
	}

	args := []string{
		"-X", "utf8", "-u", "-c", juliaWorkerScript,
		"--model", config.ModelPath,
		"--device", config.Device,
		"--max-length", strconv.Itoa(config.MaxLength),
		"--head-length", strconv.Itoa(config.HeadLength),
		"--fp-threshold", strconv.FormatFloat(config.FPThreshold, 'f', -1, 64),
		"--decision-threshold", strconv.FormatFloat(config.DecisionThreshold, 'f', -1, 64),
	}
	cmd := exec.Command(config.PythonExecutable, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create semantic worker stdin: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create semantic worker stdout: %w", err)
	}
	stderr := &boundedBuffer{limit: 64 * 1024}
	cmd.Stderr = stderr

	classifier := &JuliaClassifier{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdoutPipe, 128*1024),
		stderr: stderr,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start semantic worker: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.StartupTimeout)
	defer cancel()
	response, err := classifier.readResponse(ctx)
	if err != nil {
		classifier.terminate()
		return nil, fmt.Errorf("start semantic worker: %w%s", err, classifier.stderrSuffix())
	}
	if response.Type != "ready" {
		classifier.terminate()
		if response.Error == "" {
			response.Error = "worker did not report ready"
		}
		return nil, fmt.Errorf("start semantic worker: %s%s", response.Error, classifier.stderrSuffix())
	}
	return classifier, nil
}

func (c *JuliaClassifier) Classify(ctx context.Context, candidates []Candidate) ([]Prediction, error) {
	if len(candidates) == 0 {
		return []Prediction{}, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("semantic worker is closed")
	}
	if c.broken != nil {
		return nil, c.broken
	}

	requestID := c.request.Add(1)
	request := workerRequest{Type: "classify", ID: requestID, Candidates: candidates}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode semantic request: %w", err)
	}
	encoded = append(encoded, '\n')
	if _, err := c.stdin.Write(encoded); err != nil {
		c.broken = fmt.Errorf("write semantic request: %w", err)
		return nil, c.broken
	}

	response, err := c.readResponse(ctx)
	if err != nil {
		c.broken = fmt.Errorf("read semantic response: %w%s", err, c.stderrSuffix())
		c.terminateLocked()
		return nil, c.broken
	}
	if response.ID != requestID {
		c.broken = fmt.Errorf("semantic worker response id mismatch: got %d, expected %d", response.ID, requestID)
		c.terminateLocked()
		return nil, c.broken
	}
	if response.Type == "error" {
		return nil, fmt.Errorf("semantic worker: %s", response.Error)
	}
	if response.Type != "result" {
		return nil, fmt.Errorf("semantic worker returned unexpected response type %q", response.Type)
	}
	return response.Results, nil
}

func (c *JuliaClassifier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.waitErr
	}
	c.closed = true

	if c.cmd.Process == nil {
		return nil
	}
	request, _ := json.Marshal(workerRequest{Type: "shutdown"})
	request = append(request, '\n')
	_, _ = c.stdin.Write(request)
	_ = c.stdin.Close()

	done := make(chan error, 1)
	go func() {
		done <- c.wait()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		_ = c.cmd.Process.Kill()
		return <-done
	}
}

func (c *JuliaClassifier) readResponse(ctx context.Context) (workerResponse, error) {
	type readResult struct {
		response workerResponse
		err      error
	}
	result := make(chan readResult, 1)
	go func() {
		line, err := c.stdout.ReadBytes('\n')
		if err != nil {
			result <- readResult{err: err}
			return
		}
		var response workerResponse
		if err := json.Unmarshal(line, &response); err != nil {
			result <- readResult{err: fmt.Errorf("decode worker response: %w", err)}
			return
		}
		result <- readResult{response: response}
	}()

	select {
	case item := <-result:
		return item.response, item.err
	case <-ctx.Done():
		return workerResponse{}, ctx.Err()
	}
}

func (c *JuliaClassifier) terminate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.terminateLocked()
}

func (c *JuliaClassifier) terminateLocked() {
	if c.closed {
		return
	}
	c.closed = true
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.wait()
}

func (c *JuliaClassifier) wait() error {
	c.waitOnce.Do(func() {
		c.waitErr = c.cmd.Wait()
	})
	return c.waitErr
}

func (c *JuliaClassifier) stderrSuffix() string {
	message := strings.TrimSpace(c.stderr.String())
	if message == "" {
		return ""
	}
	return ": " + message
}

type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	originalLength := len(data)
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		b.data = append(b.data, data...)
	}
	return originalLength, nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}
