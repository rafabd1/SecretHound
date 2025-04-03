package utils

import (
	"context"
	"sync"
	"time"
)

// WorkerPool manages a pool of worker goroutines
type WorkerPool struct {
	numWorkers   int
	jobQueue     chan jobTask
	results      chan interface{}
	errors       chan error
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	activeJobs   int
	activeJobsMu sync.Mutex
	queueSize    int
	mu           sync.Mutex
	isClosed     bool
}

// jobTask represents a job to be executed by a worker
type jobTask struct {
	task func() (interface{}, error)
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers, queueSize int) *WorkerPool {
	if numWorkers <= 0 {
		numWorkers = 1
	}
	if queueSize <= 0 {
		queueSize = numWorkers * 2
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	wp := &WorkerPool{
		numWorkers: numWorkers,
		jobQueue:   make(chan jobTask, queueSize),
		results:    make(chan interface{}, queueSize),
		errors:     make(chan error, queueSize),
		done:       make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		queueSize:  queueSize,
	}
	
	// Start the worker pool
	wp.start()
	
	return wp
}

// start starts the worker pool
func (wp *WorkerPool) start() {
	// Start workers
	for i := 0; i < wp.numWorkers; i++ {
		go wp.worker(i)
	}
	
	// Start a goroutine to close the done channel when all jobs are processed
	go func() {
		// Wait for context cancellation
		<-wp.ctx.Done()
		
		// Wait for all workers to finish their current jobs
		wp.mu.Lock()
		jobsClosed := wp.isClosed
		wp.mu.Unlock()
		
		if !jobsClosed {
			// Close the job queue if not closed already to stop workers
			wp.mu.Lock()
			if !wp.isClosed {
				close(wp.jobQueue)
				wp.isClosed = true
			}
			wp.mu.Unlock()
		}
		
		// Wait until all active jobs are completed
		for {
			wp.activeJobsMu.Lock()
			active := wp.activeJobs
			wp.activeJobsMu.Unlock()
			
			if active == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		
		// Close result/error channels
		close(wp.results)
		close(wp.errors)
		
		// Signal that all jobs are done
		close(wp.done)
	}()
}

// worker is a goroutine that processes jobs from the job queue
func (wp *WorkerPool) worker(id int) {
	for {
		select {
		case <-wp.ctx.Done():
			// Context was cancelled, exit
			return
			
		case job, ok := <-wp.jobQueue:
			if (!ok) {
				// Job queue was closed, exit
				return
			}
			
			// Track active jobs
			wp.activeJobsMu.Lock()
			wp.activeJobs++
			wp.activeJobsMu.Unlock()
			
			// Execute the job
			result, err := job.task()
			
			// Update active jobs count
			wp.activeJobsMu.Lock()
			wp.activeJobs--
			wp.activeJobsMu.Unlock()
			
			// Send the result or error
			if err != nil {
				select {
				case wp.errors <- err:
				default:
					// Channel is full, discard the error
				}
			} else if result != nil {
				select {
				case wp.results <- result:
				default:
					// Channel is full, discard the result
				}
			}
		}
	}
}

// Submit submits a job to the worker pool
func (wp *WorkerPool) Submit(taskFunc func() (interface{}, error)) {
	// Check if the context is cancelled
	select {
	case <-wp.ctx.Done():
		// Context cancelled, don't submit new jobs
		return
	default:
		// Continue
	}
	
	wp.mu.Lock()
	closed := wp.isClosed
	wp.mu.Unlock()
	
	if closed {
		return // Don't add to closed queue
	}
	
	// Create a job and send it to the job queue
	job := jobTask{
		task: taskFunc,
	}
	
	wp.jobQueue <- job
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.results
}

// Errors returns the errors channel
func (wp *WorkerPool) Errors() <-chan error {
	return wp.errors
}

// Wait waits for all jobs to complete
func (wp *WorkerPool) Wait() {
	<-wp.done
}

// WaitWithTimeout waits for all jobs to complete with a timeout
func (wp *WorkerPool) WaitWithTimeout(timeout time.Duration) bool {
	select {
	case <-wp.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Shutdown shuts down the worker pool gracefully
func (wp *WorkerPool) Shutdown() {
	// Signal to all workers to stop
	wp.cancel()
	// Wait for all workers to finish
	wp.Wait()
}

// ShutdownNow shuts down the worker pool immediately
func (wp *WorkerPool) ShutdownNow() {
	// Signal to all workers to stop
	wp.cancel()
	
	wp.mu.Lock()
	if (!wp.isClosed) {
		// Close the job queue
		close(wp.jobQueue)
		wp.isClosed = true
	}
	wp.mu.Unlock()
	
	// Give workers a short time to detect shutdown
	time.Sleep(10 * time.Millisecond)
}

// ActiveJobs returns the number of active jobs
func (wp *WorkerPool) ActiveJobs() int {
	wp.activeJobsMu.Lock()
	defer wp.activeJobsMu.Unlock()
	return wp.activeJobs
}

// QueueSize returns the size of the job queue
func (wp *WorkerPool) QueueSize() int {
	return wp.queueSize
}

// WorkerCount returns the number of workers
func (wp *WorkerPool) WorkerCount() int {
	return wp.numWorkers
}

// Utilization returns the utilization of the worker pool as a percentage
func (wp *WorkerPool) Utilization() float64 {
	wp.activeJobsMu.Lock()
	defer wp.activeJobsMu.Unlock()
	return float64(wp.activeJobs) / float64(wp.numWorkers) * 100.0
}

// SimpleWorkerPool implements a simpler worker pool
type SimpleWorkerPool struct {
	workers    int
	tasks      chan func() (interface{}, error)
	results    chan interface{}
	errors     chan error
	waitGroup  sync.WaitGroup
	shutdown   chan struct{}
	isShutdown bool
	mu         sync.Mutex
}

// NewSimpleWorkerPool creates a new simple worker pool
func NewSimpleWorkerPool(workers int, queueSize int) *SimpleWorkerPool {
	if workers <= 0 {
		workers = 1
	}
	if queueSize <= 0 {
		queueSize = workers * 2
	}

	pool := &SimpleWorkerPool{
		workers:  workers,
		tasks:    make(chan func() (interface{}, error), queueSize),
		results:  make(chan interface{}, queueSize),
		errors:   make(chan error, queueSize),
		shutdown: make(chan struct{}),
	}

	// Start workers
	for i := 0; i < workers; i++ {
		pool.waitGroup.Add(1)
		go pool.worker()
	}

	// Start results collector
	go pool.collector()

	return pool
}

// worker processes tasks
func (p *SimpleWorkerPool) worker() {
	defer p.waitGroup.Done()

	for {
		select {
		case <-p.shutdown:
			return
		case task, ok := <-p.tasks:
			if (!ok) {
				return
			}

			// Execute task
			result, err := task()
			if err != nil {
				// Send error to errors channel (non-blocking)
				select {
				case p.errors <- err:
				default:
					// Channel full, log or discard
				}
			} else if result != nil {
				// Send result to results channel (non-blocking)
				select {
				case p.results <- result:
				default:
					// Channel full, log or discard
				}
			}
		}
	}
}

// collector ensures channels are closed after all tasks are processed
func (p *SimpleWorkerPool) collector() {
	// Wait for all workers to finish
	p.waitGroup.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Mark as shutdown
	p.isShutdown = true

	// Close results and errors channels
	close(p.results)
	close(p.errors)
}

// Submit submits a task to the pool
func (p *SimpleWorkerPool) Submit(task func() (interface{}, error)) {
	p.mu.Lock()
	isShutdown := p.isShutdown
	p.mu.Unlock()

	if isShutdown {
		return // Don't accept new tasks after shutdown
	}

	p.tasks <- task
}

// Results returns the results channel
func (p *SimpleWorkerPool) Results() <-chan interface{} {
	return p.results
}

// Errors returns the errors channel
func (p *SimpleWorkerPool) Errors() <-chan error {
	return p.errors
}

// Shutdown gracefully shuts down the pool
func (p *SimpleWorkerPool) Shutdown() {
	// Signal workers to stop
	close(p.shutdown)
}

// ShutdownNow forcefully shuts down the pool
func (p *SimpleWorkerPool) ShutdownNow() {
	close(p.shutdown)
	
	p.mu.Lock()
	if (!p.isShutdown) {
		close(p.tasks)
		p.isShutdown = true
	}
	p.mu.Unlock()
}

// BoundedSemaphore implements a counting semaphore
type BoundedSemaphore struct {
	permits int
	tokens  chan struct{}
}

// NewBoundedSemaphore creates a new bounded semaphore
func NewBoundedSemaphore(permits int) *BoundedSemaphore {
	if permits <= 0 {
		permits = 1
	}
	return &BoundedSemaphore{
		permits: permits,
		tokens:  make(chan struct{}, permits),
	}
}

// Acquire acquires a permit from the semaphore, blocking until one is available
func (s *BoundedSemaphore) Acquire() {
	s.tokens <- struct{}{}
}

// AcquireWithTimeout acquires a permit from the semaphore with a timeout
func (s *BoundedSemaphore) AcquireWithTimeout(timeout time.Duration) bool {
	select {
	case s.tokens <- struct{}{}:
		return true
	case <-time.After(timeout):
		return false
	}
}

// TryAcquire attempts to acquire a permit from the semaphore without blocking
func (s *BoundedSemaphore) TryAcquire() bool {
	select {
	case s.tokens <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a permit back to the semaphore
func (s *BoundedSemaphore) Release() {
	select {
	case <-s.tokens:
	default:
		// This should not happen in normal operation
		// but prevents deadlock if Release is called more times than Acquire
	}
}

// AvailablePermits returns the number of available permits
func (s *BoundedSemaphore) AvailablePermits() int {
	return s.permits - len(s.tokens)
}

// ExecuteConcurrently executes a task function for each item in a slice concurrently
func ExecuteConcurrently[T any](items []T, concurrency int, taskFn func(T) error) []error {
	if concurrency <= 0 {
		concurrency = 1
	}
	
	if len(items) == 0 {
		return nil
	}
	
	// Create channels for coordination
	jobs := make(chan T, len(items))
	results := make(chan error, len(items))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				results <- taskFn(item)
			}
		}()
	}
	
	// Send all items to the jobs channel
	for _, item := range items {
		jobs <- item
	}
	close(jobs)
	
	// Wait for all workers to finish
	wg.Wait()
	close(results)
	
	// Collect errors
	var errors []error
	for err := range results {
		if err != nil {
			errors = append(errors, err)
		}
	}
	
	return errors
}

// Throttle creates a function that throttles calls to the given function
func Throttle(f func(), interval time.Duration) func() {
	lastRun := time.Now().Add(-interval)
	var mu sync.Mutex
	
	return func() {
		mu.Lock()
		defer mu.Unlock()
		
		now := time.Now()
		if now.Sub(lastRun) >= interval {
			lastRun = now
			go f()
		}
	}
}

// Debounce creates a function that debounces calls to the given function
func Debounce(f func(), wait time.Duration) func() {
	var timer *time.Timer
	var mu sync.Mutex
	
	return func() {
		mu.Lock()
		defer mu.Unlock()
		
		if timer != nil {
			timer.Stop()
		}
		
		timer = time.AfterFunc(wait, f)
	}
}

// RunWithTimeout runs a function with a timeout
func RunWithTimeout(timeout time.Duration, f func() (interface{}, error)) (interface{}, error) {
	resultChan := make(chan struct {
		result interface{}
		err    error
	}, 1)
	
	go func() {
		result, err := f()
		resultChan <- struct {
			result interface{}
			err    error
		}{result, err}
	}()
	
	select {
	case r := <-resultChan:
		return r.result, r.err
	case <-time.After(timeout):
		return nil, ErrTimeout
	}
}

// As funções abaixo foram removidas pois estão duplicadas em outros arquivos:
// - RunWithTimeout
// - Debounce
// - Throttle
