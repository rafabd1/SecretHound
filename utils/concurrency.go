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
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	queueSize    int
	activeJobs   int
	activeJobsMu sync.Mutex
}

// jobTask represents a job to be executed by a worker
type jobTask struct {
	task func() (interface{}, error)
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, jobQueueSize int) *WorkerPool {
	if numWorkers <= 0 {
		numWorkers = 1
	}
	
	if jobQueueSize <= 0 {
		jobQueueSize = numWorkers * 2
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &WorkerPool{
		numWorkers: numWorkers,
		jobQueue:   make(chan jobTask, jobQueueSize),
		results:    make(chan interface{}, jobQueueSize),
		errors:     make(chan error, jobQueueSize),
		done:       make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		queueSize:  jobQueueSize,
	}
	
	// Start the worker goroutines
	pool.start()
	
	return pool
}

// start starts the worker pool
func (wp *WorkerPool) start() {
	// Start the worker goroutines
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
	
	// Start a goroutine to close the results and errors channels when all workers are done
	go func() {
		// Wait for all workers to finish
		wp.wg.Wait()
		// Close the done channel to signal that all workers are done
		close(wp.done)
		// Close the results and errors channels
		close(wp.results)
		close(wp.errors)
	}()
}

// worker is a goroutine that processes jobs from the job queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	
	for {
		select {
		case <-wp.ctx.Done():
			// Context was cancelled, exit
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
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
				wp.errors <- err
			} else if result != nil {
				wp.results <- result
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
	
	// Create a job and send it to the job queue
	job := jobTask{
		task: taskFunc,
	}
	
	wp.jobQueue <- job
}

// SubmitFunc submits a function that returns a result and error
func (wp *WorkerPool) SubmitFunc(taskFunc func() (interface{}, error)) {
	wp.Submit(taskFunc)
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
	// Close the job queue
	close(wp.jobQueue)
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
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	
	select {
	case s.tokens <- struct{}{}:
		return true
	case <-timer.C:
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
		// This should not happen, but just in case
		panic("attempting to release more permits than acquired")
	}
}

// AvailablePermits returns the number of available permits
func (s *BoundedSemaphore) AvailablePermits() int {
	return s.permits - len(s.tokens)
}

// ExecuteConcurrently executes a task function for each item in a slice concurrently
func ExecuteConcurrently[T any, R any](items []T, concurrency int, taskFunc func(T) (R, error)) ([]R, []error) {
	if len(items) == 0 {
		return []R{}, []error{}
	}
	
	if concurrency <= 0 {
		concurrency = 1
	}
	
	if concurrency > len(items) {
		concurrency = len(items)
	}
	
	// Create a worker pool
	pool := NewWorkerPool(concurrency, len(items))
	
	// Submit jobs to the pool
	for _, item := range items {
		item := item // Create a local copy for the closure
		pool.Submit(func() (interface{}, error) {
			result, err := taskFunc(item)
			if err != nil {
				return nil, err
			}
			return result, nil
		})
	}
	
	// Collect results
	var results []R
	var errors []error
	
	// Process results
	for result := range pool.Results() {
		results = append(results, result.(R))
	}
	
	// Process errors
	for err := range pool.Errors() {
		errors = append(errors, err)
	}
	
	pool.Wait()
	
	return results, errors
}
