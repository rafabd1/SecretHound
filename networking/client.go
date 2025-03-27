package networking

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rafabd1/SecretHound/utils"
)

// Client implements an HTTP client with advanced features
type Client struct {
	httpClient    *http.Client
	rateLimiter   *RateLimiter
	filter        *ResponseFilter
	maxRetries    int
	requestHeader map[string]string
	mutex         sync.Mutex
	stats         ClientStats
}

// ClientStats tracks statistics about the client's operations
type ClientStats struct {
	RequestsAttempted int
	RequestsSucceeded int
	RequestsFailed    int
	TotalBytes        int64
	RetryCount        int
	TotalTime         time.Duration
}

// RateLimiter controls the rate of requests to domains
type RateLimiter struct {
	domain      map[string]*DomainBucket
	globalLimit int // Requests per second
	mutex       sync.Mutex
}

// DomainBucket represents the rate limit bucket for a specific domain
type DomainBucket struct {
	tokens         int
	lastRefillTime time.Time
	refillRate     int // Tokens per second
	maxTokens      int
	mutex          sync.Mutex
}

// NewClient creates a new HTTP client
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
			globalLimit: 0, // Auto-adjust
		},
		filter:     NewResponseFilter(),
		maxRetries: maxRetries,
		requestHeader: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Accept":          "application/javascript, */*",
			"Accept-Language": "en-US,en;q=0.9",
			"Connection":      "keep-alive",
		},
		stats: ClientStats{},
	}

	return client
}

// SetRequestHeader sets a custom header for all requests
func (c *Client) SetRequestHeader(key, value string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.requestHeader[key] = value
}

// SetRateLimit sets the rate limit for requests to a specific domain
func (c *Client) SetRateLimit(domain string, requestsPerSecond int) {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()

	// If domain doesn't exist in the map, create it
	if _, exists := c.rateLimiter.domain[domain]; !exists {
		c.rateLimiter.domain[domain] = &DomainBucket{
			tokens:         requestsPerSecond,
			lastRefillTime: time.Now(),
			refillRate:     requestsPerSecond,
			maxTokens:      requestsPerSecond,
		}
	} else {
		// Update the existing domain's rate limit
		bucket := c.rateLimiter.domain[domain]
		bucket.mutex.Lock()
		bucket.refillRate = requestsPerSecond
		bucket.maxTokens = requestsPerSecond
		bucket.mutex.Unlock()
	}
}

// GetJSContent fetches JavaScript content from a URL
func (c *Client) GetJSContent(urlStr string) (string, error) {
	// Track statistics
	c.mutex.Lock()
	c.stats.RequestsAttempted++
	c.mutex.Unlock()

	startTime := time.Now()

	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed to parse URL: %s", urlStr), err)
	}

	// Extract the domain
	domain := parsedURL.Hostname()

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer cancel()

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed to create request for URL: %s", urlStr), err)
	}

	// Add headers
	for key, value := range c.requestHeader {
		req.Header.Set(key, value)
	}

	// Implement retry logic
	var (
		resp        *http.Response
		retryCount  int
		shouldRetry bool
		retryDelay  time.Duration
	)

	for retryCount = 0; retryCount <= c.maxRetries; retryCount++ {
		// Apply rate limiting if needed
		if err := c.checkRateLimit(domain); err != nil {
			retryDelay = c.calculateBackoff(retryCount, domain)
			time.Sleep(retryDelay)
			continue
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return "", utils.NewError(utils.NetworkError, "request timed out", err)
			}
			
			// Check if we should retry for network errors
			if retryCount < c.maxRetries {
				retryDelay = c.calculateBackoff(retryCount, domain)
				time.Sleep(retryDelay)
				continue
			}
			
			return "", utils.NewError(utils.NetworkError, fmt.Sprintf("network error after %d retries", retryCount), err)
		}

		// Check the response
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success
			break
		}

		// Close the response body to avoid resource leaks
		resp.Body.Close()

		// Check if the response indicates rate limiting or WAF
		if c.filter.IsRateLimited(resp) {
			return "", utils.NewError(utils.RateLimitError, "rate limited by server", nil)
		}

		if c.filter.IsWAFBlocked(resp) {
			return "", utils.NewError(utils.WAFError, "blocked by WAF", nil)
		}

		// Check if we should retry based on status code
		shouldRetry, retryDelay = c.shouldRetryStatus(resp.StatusCode, retryCount, domain)
		if !shouldRetry || retryCount >= c.maxRetries {
			return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed with status code: %d", resp.StatusCode), nil)
		}

		time.Sleep(retryDelay)
	}

	// Track retry statistics
	if retryCount > 0 {
		c.mutex.Lock()
		c.stats.RetryCount += retryCount
		c.mutex.Unlock()
	}

	// Read the response body
	if resp == nil {
		return "", utils.NewError(utils.NetworkError, "no response after retries", nil)
	}
	defer resp.Body.Close()

	// Check if the response should be processed
	if !c.filter.ShouldProcess(resp) {
		return "", utils.NewError(utils.NetworkError, fmt.Sprintf("response filtered out (status code: %d)", resp.StatusCode), nil)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", utils.NewError(utils.NetworkError, "failed to read response body", err)
	}

	// Update statistics
	c.mutex.Lock()
	c.stats.RequestsSucceeded++
	c.stats.TotalBytes += int64(len(body))
	c.stats.TotalTime += time.Since(startTime)
	c.mutex.Unlock()

	return string(body), nil
}

// checkRateLimit checks if a request can be made to a domain
func (c *Client) checkRateLimit(domain string) error {
	c.rateLimiter.mutex.Lock()
	
	// If domain doesn't exist in the map, create it with a default rate
	if _, exists := c.rateLimiter.domain[domain]; !exists {
		defaultRate := 3 // Default to 3 requests per second
		if c.rateLimiter.globalLimit > 0 {
			defaultRate = c.rateLimiter.globalLimit
		}
		
		c.rateLimiter.domain[domain] = &DomainBucket{
			tokens:         defaultRate,
			lastRefillTime: time.Now(),
			refillRate:     defaultRate,
			maxTokens:      defaultRate,
		}
	}
	
	bucket := c.rateLimiter.domain[domain]
	c.rateLimiter.mutex.Unlock()

	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefillTime).Seconds()
	tokensToAdd := int(elapsed * float64(bucket.refillRate))
	
	if tokensToAdd > 0 {
		bucket.tokens = bucket.tokens + tokensToAdd
		if bucket.tokens > bucket.maxTokens {
			bucket.tokens = bucket.maxTokens
		}
		bucket.lastRefillTime = now
	}

	// Check if we have tokens available
	if bucket.tokens < 1 {
		return utils.NewError(utils.RateLimitError, "rate limit exceeded for domain", nil)
	}

	// Consume a token
	bucket.tokens--
	return nil
}

// GetRateLimit returns the default rate limit per domain
func (c *Client) GetRateLimit() int {
    if c.rateLimiter == nil || len(c.rateLimiter.domain) == 0 {
        return 3 // Default rate limit
    }
    // Return the first domain's rate limit as the default
    for _, bucket := range c.rateLimiter.domain {
        return bucket.refillRate
    }
    return 3
}

// shouldRetryStatus determines if a request should be retried based on the status code
func (c *Client) shouldRetryStatus(statusCode int, retryCount int, domain string) (bool, time.Duration) {
	switch {
	case statusCode >= 500:
		// Server errors
		return true, c.calculateBackoff(retryCount, domain)
	case statusCode == 429:
		// Too Many Requests
		return true, c.calculateBackoff(retryCount, domain) * 2 // Double the backoff for rate limiting
	case statusCode >= 400 && statusCode < 500:
		// Client errors (except 429)
		if statusCode == 408 || statusCode == 425 {
			// Request timeout or too early
			return true, c.calculateBackoff(retryCount, domain)
		}
		// Other client errors are not retried
		return false, 0
	default:
		// Other status codes are not retried
		return false, 0
	}
}

// calculateBackoff calculates the backoff time for retries using exponential backoff
func (c *Client) calculateBackoff(retryCount int, domain string) time.Duration {
	// Start with 1 second and double for each retry with some randomness
	baseDelay := time.Duration(1<<uint(retryCount)) * time.Second
	
	// Add jitter to avoid thundering herd problem
	jitterFactor := 0.5 + 0.5*utils.RandomFloat()
	delay := time.Duration(float64(baseDelay) * jitterFactor)
	
	// Cap at 30 seconds
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	
	return delay
}

// GetStats returns the client's statistics
func (c *Client) GetStats() ClientStats {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Create a copy to avoid race conditions
	return ClientStats{
		RequestsAttempted: c.stats.RequestsAttempted,
		RequestsSucceeded: c.stats.RequestsSucceeded,
		RequestsFailed:    c.stats.RequestsFailed,
		TotalBytes:        c.stats.TotalBytes,
		RetryCount:        c.stats.RetryCount,
		TotalTime:         c.stats.TotalTime,
	}
}

// ResetStats resets the client's statistics
func (c *Client) ResetStats() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.stats = ClientStats{}
}
