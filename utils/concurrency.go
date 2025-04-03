package utils

import (
	"context"
	"sync"
	"time"
)

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

type jobTask struct {
	task func() (interface{}, error)
}

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
	
	wp.start()
	
	return wp
}

func (wp *WorkerPool) start() {
	for i := 0; i < wp.numWorkers; i++ {
		go wp.worker(i)
	}
	
	go func() {
		<-wp.ctx.Done()
		
		wp.mu.Lock()
		jobsClosed := wp.isClosed
		wp.mu.Unlock()
		
		if !jobsClosed {
			wp.mu.Lock()
			if !wp.isClosed {
				close(wp.jobQueue)
				wp.isClosed = true
			}
			wp.mu.Unlock()
		}
		
		for {
			wp.activeJobsMu.Lock()
			active := wp.activeJobs
			wp.activeJobsMu.Unlock()
			
			if active == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		
		close(wp.results)
		close(wp.errors)
		close(wp.done)
	}()
}

func (wp *WorkerPool) worker(id int) {
	for {
		select {
		case <-wp.ctx.Done():
			return
			
		case job, ok := <-wp.jobQueue:
			if (!ok) {
				return
			}
			
			wp.activeJobsMu.Lock()
			wp.activeJobs++
			wp.activeJobsMu.Unlock()
			
			result, err := job.task()
			
			wp.activeJobsMu.Lock()
			wp.activeJobs--
			wp.activeJobsMu.Unlock()
			
			if err != nil {
				select {
				case wp.errors <- err:
				default:
				}
			} else if result != nil {
				select {
				case wp.results <- result:
				default:
				}
			}
		}
	}
}

func (wp *WorkerPool) Submit(taskFunc func() (interface{}, error)) {
	select {
	case <-wp.ctx.Done():
		return
	default:
	}
	
	wp.mu.Lock()
	closed := wp.isClosed
	wp.mu.Unlock()
	
	if closed {
		return
	}
	
	job := jobTask{
		task: taskFunc,
	}
	
	wp.jobQueue <- job
}

func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.results
}

func (wp *WorkerPool) Errors() <-chan error {
	return wp.errors
}

func (wp *WorkerPool) Wait() {
	<-wp.done
}

func (wp *WorkerPool) WaitWithTimeout(timeout time.Duration) bool {
	select {
	case <-wp.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (wp *WorkerPool) Shutdown() {
	wp.cancel()
	wp.Wait()
}

func (wp *WorkerPool) ShutdownNow() {
	wp.cancel()
	
	wp.mu.Lock()
	if (!wp.isClosed) {
		close(wp.jobQueue)
		wp.isClosed = true
	}
	wp.mu.Unlock()
	
	time.Sleep(10 * time.Millisecond)
}

func (wp *WorkerPool) ActiveJobs() int {
	wp.activeJobsMu.Lock()
	defer wp.activeJobsMu.Unlock()
	return wp.activeJobs
}

func (wp *WorkerPool) QueueSize() int {
	return wp.queueSize
}

func (wp *WorkerPool) WorkerCount() int {
	return wp.numWorkers
}

func (wp *WorkerPool) Utilization() float64 {
	wp.activeJobsMu.Lock()
	defer wp.activeJobsMu.Unlock()
	return float64(wp.activeJobs) / float64(wp.numWorkers) * 100.0
}

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

	for i := 0; i < workers; i++ {
		pool.waitGroup.Add(1)
		go pool.worker()
	}

	go pool.collector()

	return pool
}

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

			result, err := task()
			if err != nil {
				select {
				case p.errors <- err:
				default:
				}
			} else if result != nil {
				select {
				case p.results <- result:
				default:
				}
			}
		}
	}
}

/* 
   Ensures channels are closed after all tasks are processed
*/
func (p *SimpleWorkerPool) collector() {
	p.waitGroup.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.isShutdown = true

	close(p.results)
	close(p.errors)
}

func (p *SimpleWorkerPool) Submit(task func() (interface{}, error)) {
	p.mu.Lock()
	isShutdown := p.isShutdown
	p.mu.Unlock()

	if isShutdown {
		return
	}

	p.tasks <- task
}

func (p *SimpleWorkerPool) Results() <-chan interface{} {
	return p.results
}

func (p *SimpleWorkerPool) Errors() <-chan error {
	return p.errors
}

func (p *SimpleWorkerPool) Shutdown() {
	close(p.shutdown)
}

func (p *SimpleWorkerPool) ShutdownNow() {
	close(p.shutdown)
	
	p.mu.Lock()
	if (!p.isShutdown) {
		close(p.tasks)
		p.isShutdown = true
	}
	p.mu.Unlock()
}

type BoundedSemaphore struct {
	permits int
	tokens  chan struct{}
}

func NewBoundedSemaphore(permits int) *BoundedSemaphore {
	if permits <= 0 {
		permits = 1
	}
	return &BoundedSemaphore{
		permits: permits,
		tokens:  make(chan struct{}, permits),
	}
}

func (s *BoundedSemaphore) Acquire() {
	s.tokens <- struct{}{}
}

func (s *BoundedSemaphore) AcquireWithTimeout(timeout time.Duration) bool {
	select {
	case s.tokens <- struct{}{}:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *BoundedSemaphore) TryAcquire() bool {
	select {
	case s.tokens <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *BoundedSemaphore) Release() {
	select {
	case <-s.tokens:
	default:
	}
}

func (s *BoundedSemaphore) AvailablePermits() int {
	return s.permits - len(s.tokens)
}

/* 
   Executes a task function for each item in a slice concurrently with limited concurrency
*/
func ExecuteConcurrently[T any](items []T, concurrency int, taskFn func(T) error) []error {
	if concurrency <= 0 {
		concurrency = 1
	}
	
	if len(items) == 0 {
		return nil
	}
	
	jobs := make(chan T, len(items))
	results := make(chan error, len(items))
	
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
	
	for _, item := range items {
		jobs <- item
	}
	close(jobs)
	
	wg.Wait()
	close(results)
	
	var errors []error
	for err := range results {
		if err != nil {
			errors = append(errors, err)
		}
	}
	
	return errors
}

/* 
   Creates a function that limits the rate at which the original function is called
*/
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

/* 
   Creates a function that delays calling the original function until after wait duration
   has elapsed since the last time it was invoked
*/
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
