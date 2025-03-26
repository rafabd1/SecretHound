package utils

import (
	"sync"
	"time"
)

// WorkerPool implements a simple, robust worker pool
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

// NewSimpleWorkerPool creates a new worker pool
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

	// Start results collector (to prevent blocking even if results aren't read)
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
			if !ok {
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
	p.mu.Lock()
	if p.isShutdown {
		p.mu.Unlock()
		return
	}
	close(p.tasks)  // Stop accepting new tasks
	p.mu.Unlock()

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.waitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers finished normally
	case <-time.After(5 * time.Second):
		// Timeout, signal hard shutdown
		close(p.shutdown)
	}
}

// ShutdownNow forcefully shuts down the pool
func (p *SimpleWorkerPool) ShutdownNow() {
	p.mu.Lock()
	if p.isShutdown {
		p.mu.Unlock()
		return
	}
	p.isShutdown = true
	close(p.tasks)  // Stop accepting new tasks
	close(p.shutdown) // Signal workers to exit immediately
	p.mu.Unlock()

	// Give workers a moment to respond to shutdown signal
	time.Sleep(10 * time.Millisecond)
}

// Wait waits for all tasks to complete
func (p *SimpleWorkerPool) Wait() {
	p.mu.Lock()
	if p.isShutdown {
		p.mu.Unlock()
		return
	}
	close(p.tasks) // Stop accepting new tasks
	p.mu.Unlock()

	// Wait for all workers to finish
	p.waitGroup.Wait()
}
