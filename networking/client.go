package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

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
}

type ClientStats struct {
	RequestsAttempted int
	RequestsSucceeded int
	RequestsFailed    int
	TotalBytes        int64
	RetryCount        int
	TotalTime         time.Duration
}

type RateLimiter struct {
	domain      map[string]*DomainBucket
	globalLimit int
	mutex       sync.Mutex
}

type DomainBucket struct {
	tokens         int
	lastRefillTime time.Time
	refillRate     int
	maxTokens      int
	mutex          sync.Mutex
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
	
	c.rateLimiter.globalLimit = requestsPerSecond
	
	for _, bucket := range c.rateLimiter.domain {
		bucket.mutex.Lock()
		bucket.refillRate = requestsPerSecond
		bucket.maxTokens = requestsPerSecond
		bucket.tokens = requestsPerSecond 
		bucket.mutex.Unlock()
	}
}

func (c *Client) SetRateLimit(domain string, requestsPerSecond int) {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()

	if _, exists := c.rateLimiter.domain[domain]; !exists {
		c.rateLimiter.domain[domain] = &DomainBucket{
			tokens:         requestsPerSecond,
			lastRefillTime: time.Now(),
			refillRate:     requestsPerSecond,
			maxTokens:      requestsPerSecond,
		}
	} else {
		bucket := c.rateLimiter.domain[domain]
		bucket.mutex.Lock()
		bucket.refillRate = requestsPerSecond
		bucket.maxTokens = requestsPerSecond
		bucket.mutex.Unlock()
	}
}

/* 
   Fetches JavaScript content from a URL with retry logic and rate limiting
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
			retryDelay = c.calculateBackoff(retryCount, domain)
			time.Sleep(retryDelay)
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
					retryDelay = c.calculateBackoff(retryCount, domain)
					time.Sleep(retryDelay)
					continue
				}
				
				return "", utils.NewError(utils.NetworkError, fmt.Sprintf("network error after %d retries", retryCount), requestErr)
			}
			
			defer cancel()
			
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				break
			}

			resp.Body.Close()

			if c.filter.IsRateLimited(resp) {
				return "", utils.NewError(utils.RateLimitError, "rate limited by server", nil)
			}

			if c.filter.IsWAFBlocked(resp) {
				return "", utils.NewError(utils.WAFError, "blocked by WAF", nil)
			}

			shouldRetry, retryDelay = c.shouldRetryStatus(resp.StatusCode, retryCount, domain)
			if !shouldRetry || retryCount >= c.maxRetries {
				return "", utils.NewError(utils.NetworkError, fmt.Sprintf("failed with status code: %d", resp.StatusCode), nil)
			}

			time.Sleep(retryDelay)
		}
	}

	if retryCount > 0 {
		c.mutex.Lock()
		c.stats.RetryCount += retryCount
		c.mutex.Unlock()
	}

	if resp == nil {
		return "", utils.NewError(utils.NetworkError, "no response after retries", nil)
	}
	
	bodyCtx, bodyCancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer bodyCancel()
	
	bodyReadComplete := make(chan struct{})
	
	var bodyBytes []byte
	var bodyErr error
	
	go func() {
		bodyBytes, bodyErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		close(bodyReadComplete)
	}()
	
	select {
	case <-bodyCtx.Done():
		return "", utils.NewError(utils.NetworkError, "timed out while reading response body", bodyCtx.Err())
	case <-bodyReadComplete:
		if bodyErr != nil {
			return "", utils.NewError(utils.NetworkError, "failed to read response body", bodyErr)
		}
	}

	c.mutex.Lock()
	c.stats.RequestsSucceeded++
	c.stats.TotalBytes += int64(len(bodyBytes))
	c.stats.TotalTime += time.Since(startTime)
	c.mutex.Unlock()

	return string(bodyBytes), nil
}

/* 
   Checks if a request can be made to a domain based on rate limits
*/
func (c *Client) checkRateLimit(domain string) error {
	c.rateLimiter.mutex.Lock()
	
	if _, exists := c.rateLimiter.domain[domain]; !exists {
		defaultRate := 3
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

	if bucket.tokens < 1 {
		return utils.NewError(utils.RateLimitError, "rate limit exceeded for domain", nil)
	}

	bucket.tokens--
	return nil
}

func (c *Client) GetRateLimit() int {
	c.rateLimiter.mutex.Lock()
	defer c.rateLimiter.mutex.Unlock()
	
	if c.rateLimiter.globalLimit > 0 {
		return c.rateLimiter.globalLimit
	}
	
	return 3
}

/* 
   Determines if a request should be retried based on HTTP status code
*/
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

/* 
   Calculates the backoff time for retries using exponential backoff with jitter
*/
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

/* 
   Configures whether the client should skip SSL/TLS certificate verification
*/
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
