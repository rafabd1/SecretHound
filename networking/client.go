package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/output"
	"github.com/rafabd1/SecretHound/utils"
)

type Client struct {
	httpClient    *http.Client
	rateLimiter   *RateLimiter
	filter        *ResponseFilter
	maxRetries    int
	requestHeader map[string]string
	mutex         sync.Mutex
	stats         ClientStats
	insecure      bool
	logger        *output.Logger
}

type ClientStats struct {
	RequestsAttempted int
	RequestsSucceeded int
	RequestsFailed    int
	TotalBytes        int64
	RetryCount        int
	TotalTime         time.Duration
}

// Adaptive rate limiting constants
const (
	DefaultAdaptiveRate = 15 // Initial rate for auto mode
	MinAdaptiveRate     = 3  // Minimum rate when limited
	MaxAdaptiveRate     = 40 // Maximum rate for auto mode
	AdaptationFactor    = 0.7 // Factor to reduce rate upon error (e.g., 10 -> 7)
	RecoveryFactor    = 1.2 // Factor to increase rate during recovery (e.g., 10 -> 12)
	RecoveryInterval  = 30 * time.Second // Time without errors before starting recovery
	FullRecoveryTime  = 2 * time.Minute  // Time without errors to reach max rate again
)

type RateLimiter struct {
	domain      map[string]*DomainBucket
	globalLimit int // Represents the FIXED limit when -l N > 0
	adaptiveMode bool // True when -l 0 (auto)
	mutex       sync.Mutex
}

type DomainBucket struct {
	tokens         float64 // Use float for finer grained refill
	lastRefillTime time.Time
	refillRate     float64 // Tokens per second
	maxTokens      float64
	mutex          sync.Mutex
	// Adaptive fields
	isAdapting     bool      // Currently reducing rate due to errors
	lastErrorTime  time.Time // Time of the last rate limit error from server
	currentRate    float64   // Actual rate being used (for adaptive mode)
}

func NewClient(timeout int, maxRetries int) *Client {
	transport := &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: transport,
		},
		rateLimiter: &RateLimiter{
			domain:      make(map[string]*DomainBucket),
			globalLimit: 0,
			adaptiveMode: true,
		},
		filter:     NewResponseFilter(),
		maxRetries: maxRetries,
		requestHeader: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Accept":          "application/javascript, */*",
			"Accept-Language": "en-US,en;q=0.9",
			"Connection":      "keep-alive",
		},
		stats:    ClientStats{},
		insecure: false,
		logger:   output.NewLogger(false),
	}

	return client
}

func (c *Client) SetRequestHeader(key, value string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.requestHeader[key] = value
}

func (c *Client) SetGlobalRateLimit(requestsPerSecond int) {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()

	if requestsPerSecond == 0 {
		// Enable Adaptive Mode
		c.rateLimiter.adaptiveMode = true
		c.rateLimiter.globalLimit = DefaultAdaptiveRate // Use default as the initial rate for new buckets
		c.logger.Debug("Adaptive rate limiting enabled.")
	} else {
		// Fixed Rate Mode
		c.rateLimiter.adaptiveMode = false
		c.rateLimiter.globalLimit = requestsPerSecond
		c.logger.Debug("Fixed rate limiting enabled: %d req/s", requestsPerSecond)
	}

	// Update existing buckets to the new mode/rate
	for _, bucket := range c.rateLimiter.domain {
		bucket.mutex.Lock()
		if c.rateLimiter.adaptiveMode {
			bucket.refillRate = float64(DefaultAdaptiveRate)
			bucket.maxTokens = float64(DefaultAdaptiveRate)
			bucket.currentRate = float64(DefaultAdaptiveRate)
			bucket.isAdapting = false // Reset adaptation state
		} else {
			bucket.refillRate = float64(c.rateLimiter.globalLimit)
			bucket.maxTokens = float64(c.rateLimiter.globalLimit)
			bucket.currentRate = float64(c.rateLimiter.globalLimit) // Fixed rate
			bucket.isAdapting = false
		}
		// Reset tokens to max for simplicity when changing modes/rates
		bucket.tokens = bucket.maxTokens
		bucket.mutex.Unlock()
	}
}

func (c *Client) SetRateLimit(domain string, requestsPerSecond int) {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()

	if c.rateLimiter.adaptiveMode {
		c.logger.Warning("Setting specific rate for %s while adaptive mode is active might lead to unexpected behavior.", domain)
	}

	if _, exists := c.rateLimiter.domain[domain]; !exists {
		c.rateLimiter.domain[domain] = &DomainBucket{
			tokens:         float64(requestsPerSecond),
			lastRefillTime: time.Now(),
			refillRate:     float64(requestsPerSecond),
			maxTokens:      float64(requestsPerSecond),
		}
	} else {
		bucket := c.rateLimiter.domain[domain]
		bucket.mutex.Lock()
		bucket.refillRate = float64(requestsPerSecond)
		bucket.maxTokens = float64(requestsPerSecond)
		bucket.mutex.Unlock()
	}
}

/* 
   Fetches JavaScript content from a URL with retry logic and adaptive rate limiting
*/
func (c *Client) GetJSContent(urlStr string) (string, error) {
	c.mutex.Lock()
	c.stats.RequestsAttempted++
	c.mutex.Unlock()

	startTime := time.Now()

	parsedURL, err := url.Parse(urlStr)
	if (err != nil) {
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed to parse URL: %s", urlStr), err)
	}

	domain := parsedURL.Hostname()

	var (
		resp        *http.Response
		retryCount  int
		shouldRetry bool
		retryDelay  time.Duration
	)

	for retryCount = 0; retryCount <= c.maxRetries; retryCount++ {
		if err := c.checkRateLimit(domain); err != nil {
			c.logger.Debug("Internal rate limit hit for %s, waiting... (%v)", domain, err)
			waitTime := time.Second / time.Duration(c.rateLimiter.getCurrentRate(domain)) 
			if waitTime < 10*time.Millisecond {
				waitTime = 10 * time.Millisecond
			}
			time.Sleep(waitTime + time.Duration(rand.Intn(50))*time.Millisecond)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)

		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			cancel()
			return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed to create request for URL: %s", urlStr), err)
		}

		for key, value := range c.requestHeader {
			req.Header.Set(key, value)
		}

		requestDone := make(chan struct{})
		var requestErr error

		go func() {
			resp, requestErr = c.httpClient.Do(req)
			close(requestDone)
		}()

		select {
		case <-ctx.Done():
			cancel()
			
			if retryCount >= c.maxRetries {
				return "", utils.NewError(utils.NetworkError, fmt.Sprintf("request to %s timed out after %d retries", urlStr, retryCount+1), ctx.Err())
			}
			
			retryDelay = c.calculateBackoff(retryCount, domain)
			time.Sleep(retryDelay)
			continue

		case <-requestDone:
			if requestErr != nil {
				cancel()
				
				if retryCount < c.maxRetries {
					c.logger.Debug("Network error for %s, retrying (%d/%d): %v", urlStr, retryCount+1, c.maxRetries, requestErr)
					retryDelay = c.calculateBackoff(retryCount, domain) 
					time.Sleep(retryDelay)
					continue
				}
				
				return "", utils.NewError(utils.NetworkError, fmt.Sprintf("network error after %d retries for %s", retryCount+1, urlStr), requestErr)
			}
			
			defer cancel()
			
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				break
			}

			var respBodyBytes []byte
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				respBodyBytes = []byte{}
			} else {
				respBodyBytes, _ = io.ReadAll(resp.Body)
			}
			resp.Body.Close()
			
			isRateLimited := c.filter.IsRateLimited(resp)
			isWAFBlocked := c.filter.IsWAFBlocked(resp)

			if isRateLimited {
				c.logger.Warning("Server rate limit detected for %s (Status: %d)", urlStr, resp.StatusCode)
				c.rateLimiter.NotifyRateLimitError(domain)
				return "", utils.NewError(utils.RateLimitError, fmt.Sprintf("server rate limited %s (Status %d)", urlStr, resp.StatusCode), nil)
			}

			if isWAFBlocked {
				c.logger.Warning("WAF block detected for %s (Status: %d)", urlStr, resp.StatusCode)
				bodyStr := string(respBodyBytes)
				if len(bodyStr) > 100 {
					bodyStr = bodyStr[:100] + "..."
				}
				c.logger.Debug("WAF Response Body Snippet: %s", bodyStr)
				return "", utils.NewError(utils.WAFError, fmt.Sprintf("WAF blocked %s (Status %d)", urlStr, resp.StatusCode), nil)
			}

			shouldRetry, retryDelay = c.shouldRetryStatus(resp.StatusCode, retryCount, domain)
			if shouldRetry && retryCount < c.maxRetries {
				c.logger.Debug("Received status %d for %s, retrying (%d/%d) after %s", resp.StatusCode, urlStr, retryCount+1, c.maxRetries, retryDelay)
				time.Sleep(retryDelay)
				continue
			}

			c.logger.Error("Failed request for %s after %d retries with status %d", urlStr, retryCount+1, resp.StatusCode)
			bodyStr := string(respBodyBytes)
			if len(bodyStr) > 100 {
				bodyStr = bodyStr[:100] + "..."
			}
			c.logger.Debug("Final Error Response Body Snippet: %s", bodyStr)
			return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed %s after %d retries (Status %d)", urlStr, retryCount+1, resp.StatusCode), nil)
		}
	}

	if retryCount > 0 {
		c.mutex.Lock()
		c.stats.RetryCount += retryCount
		c.mutex.Unlock()
	}

	if resp == nil {
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("no valid response for %s after retries", urlStr), nil)
	}
	
	bodyCtx, bodyCancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer bodyCancel()
	
	bodyReadComplete := make(chan struct{})
	
	var bodyBytes []byte
	var bodyErr error
	
	go func() {
		defer resp.Body.Close()
		bodyBytes, bodyErr = io.ReadAll(resp.Body)
		close(bodyReadComplete)
	}()
	
	select {
	case <-bodyCtx.Done():
		c.stats.RequestsFailed++
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("timeout reading body from %s", urlStr), bodyCtx.Err())
	case <-bodyReadComplete:
		if bodyErr != nil {
			c.stats.RequestsFailed++
			return "", utils.NewError(utils.NetworkError, fmt.Sprintf("error reading body from %s", urlStr), bodyErr)
		}
	}

	c.mutex.Lock()
	c.stats.RequestsSucceeded++
	c.stats.TotalBytes += int64(len(bodyBytes))
	c.stats.TotalTime += time.Since(startTime)
	c.mutex.Unlock()

	return string(bodyBytes), nil
}

func (c *Client) checkRateLimit(domain string) error {
	c.rateLimiter.mutex.Lock()
	bucket, exists := c.rateLimiter.domain[domain]
	if !exists {
		bucket = c.rateLimiter.createBucket(domain)
	}
	c.rateLimiter.mutex.Unlock()

	bucket.refill()

	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()

	if bucket.tokens >= 1.0 {
		bucket.tokens--
		return nil
	}

	return fmt.Errorf("rate limit bucket empty for domain %s (Current Rate: %.2f)", domain, bucket.currentRate)
}

func (rl *RateLimiter) createBucket(domain string) *DomainBucket {
	rate := float64(rl.globalLimit)
	if rl.adaptiveMode {
		rate = float64(DefaultAdaptiveRate)
	}

	b := &DomainBucket{
		tokens:         rate,
		lastRefillTime: time.Now(),
		refillRate:     rate,
		maxTokens:      rate,
		currentRate:    rate,
		isAdapting:     false,
	}
	rl.domain[domain] = b
	return b
}

func (b *DomainBucket) refill() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefillTime)
	if elapsed <= 0 {
		return
	}

	if b.isAdapting && time.Since(b.lastErrorTime) > RecoveryInterval {
		if time.Since(b.lastErrorTime) > FullRecoveryTime {
			b.currentRate = math.Min(float64(MaxAdaptiveRate), b.currentRate * RecoveryFactor * 2)
			if b.currentRate >= float64(MaxAdaptiveRate) {
				b.currentRate = float64(MaxAdaptiveRate)
				b.isAdapting = false
			}
		} else {
			increase := b.currentRate * (RecoveryFactor - 1.0) * (elapsed.Seconds() / FullRecoveryTime.Seconds())
			b.currentRate = math.Min(float64(MaxAdaptiveRate), b.currentRate+increase)
		}
		b.refillRate = b.currentRate
		b.maxTokens = b.currentRate
	}

	tokensToAdd := elapsed.Seconds() * b.refillRate
	b.tokens = math.Min(b.maxTokens, b.tokens+tokensToAdd)
	b.lastRefillTime = now
}

func (rl *RateLimiter) NotifyRateLimitError(domain string) {
	rl.mutex.Lock()
	bucket, exists := rl.domain[domain]
	rl.mutex.Unlock()

	if !exists || !rl.adaptiveMode {
		return
	}

	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()

	newRate := math.Max(float64(MinAdaptiveRate), bucket.currentRate*AdaptationFactor)
	bucket.currentRate = newRate
	bucket.refillRate = newRate
	bucket.maxTokens = newRate
	bucket.isAdapting = true
	bucket.lastErrorTime = time.Now()
	bucket.tokens = 0
}

func (c *Client) GetRateLimit() int {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()
	
	if c.rateLimiter.globalLimit > 0 {
		return c.rateLimiter.globalLimit
	}
	
	return 3
}

func (c *Client) shouldRetryStatus(statusCode int, retryCount int, domain string) (bool, time.Duration) {
	switch {
	case statusCode >= 500:
		return true, c.calculateBackoff(retryCount, domain)
	case statusCode == 429:
		return true, c.calculateBackoff(retryCount, domain) * 2
	case statusCode >= 400 && statusCode < 500:
		if statusCode == 408 || statusCode == 425 {
			return true, c.calculateBackoff(retryCount, domain)
		}
		return false, 0
	default:
		return false, 0
	}
}

func (c *Client) calculateBackoff(retryCount int, domain string) time.Duration {
	baseDelay := time.Duration(1<<uint(retryCount)) * time.Second
	
	jitterFactor := 0.5 + 0.5*utils.RandomFloat()
	delay := time.Duration(float64(baseDelay) * jitterFactor)
	
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	
	return delay
}

func (c *Client) GetStats() ClientStats {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	return ClientStats{
		RequestsAttempted: c.stats.RequestsAttempted,
		RequestsSucceeded: c.stats.RequestsSucceeded,
		RequestsFailed:    c.stats.RequestsFailed,
		TotalBytes:        c.stats.TotalBytes,
		RetryCount:        c.stats.RetryCount,
		TotalTime:         c.stats.TotalTime,
	}
}

func (c *Client) ResetStats() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.stats = ClientStats{}
}

func (c *Client) SetInsecureSkipVerify(insecure bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.insecure = insecure
	
	transport := &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: insecure},
	}
	
	c.httpClient.Transport = transport
}

func (rl *RateLimiter) getCurrentRate(domain string) float64 {
	rl.mutex.Lock()
	bucket, exists := rl.domain[domain]
	rl.mutex.Unlock()
	if exists {
		bucket.mutex.Lock()
		rate := bucket.currentRate
		bucket.mutex.Unlock()
		if rate < 0.1 { 
			return 0.1
		}
		return rate
	}
	if rl.adaptiveMode {
		return float64(DefaultAdaptiveRate)
	}
	return float64(rl.globalLimit)
}
