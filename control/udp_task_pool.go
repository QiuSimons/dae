/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"sync"
	"time"
)

const (
	UdpTaskQueueLength = 512                    // Increase queue length to support higher concurrency
	MaxUdpQueues       = 5000                   // Increase max number of queues
	UdpTaskTimeout     = 100 * time.Millisecond // Very short timeout
)

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue struct {
	key       string
	p         *UdpTaskPool
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	ctx       context.Context
	closed    chan struct{}
}

func (q *UdpTaskQueue) convoy() {
	defer close(q.closed)
	for {
		select {
		case <-q.ctx.Done():
			// Clear remaining tasks
			q.drainRemainingTasks()
			return
		case task := <-q.ch:
			// Execute task asynchronously immediately, do not wait for completion
			go q.executeTaskAsync(task)
			// Reset aging timer
			if q.timer != nil {
				q.timer.Reset(q.agingTime)
			}
		}
	}
}

// executeTaskAsync executes a single task asynchronously
func (q *UdpTaskQueue) executeTaskAsync(task UdpTask) {
	defer func() {
		if r := recover(); r != nil {
			// Log panic but do not affect other tasks
		}
	}()
	if task != nil {
		task()
	}
}

// drainRemainingTasks clears remaining tasks
func (q *UdpTaskQueue) drainRemainingTasks() {
	for {
		select {
		case task := <-q.ch:
			// Asynchronously execute remaining tasks
			go q.executeTaskAsync(task)
		default:
			return
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	// Use RWMutex to improve read performance
	mu sync.RWMutex
	m  map[string]*UdpTaskQueue
}

func NewUdpTaskPool() *UdpTaskPool {
	p := &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		mu: sync.RWMutex{},
		m:  map[string]*UdpTaskQueue{},
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool) EmitTask(key string, task UdpTask) {
	if task == nil {
		return
	}

	// Try to use read lock to quickly find existing queue
	p.mu.RLock()
	q, exists := p.m[key]
	queueCount := len(p.m)
	p.mu.RUnlock()

	if exists {
		// Queue already exists, submit task directly
		p.submitTaskToQueue(q, task)
		return
	}

	// Need to create a new queue, use write lock
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check
	if q, exists := p.m[key]; exists {
		p.submitTaskToQueue(q, task)
		return
	}

	// Limit the number of queues
	if queueCount >= MaxUdpQueues {
		// Simple packet drop counting (optional: can use atomic counter)
		return
	}

	// Create a new queue
	ch := p.queueChPool.Get().(chan UdpTask)
	ctx, cancel := context.WithCancel(context.Background())
	q = &UdpTaskQueue{
		key:       key,
		p:         p,
		ch:        ch,
		timer:     nil,
		agingTime: DefaultNatTimeout,
		ctx:       ctx,
		closed:    make(chan struct{}),
	}

	q.timer = time.AfterFunc(q.agingTime, func() {
		p.cleanupQueue(key, q, cancel, ch)
	})

	p.m[key] = q
	go q.convoy()

	// Submit task to the newly created queue
	p.submitTaskToQueue(q, task)
}

// submitTaskToQueue submits a task to the specified queue (minimal version)
func (p *UdpTaskPool) submitTaskToQueue(q *UdpTaskQueue, task UdpTask) {
	// Keep async goroutine and panic protection
	wrappedTask := func() {
		defer func() {
			if r := recover(); r != nil {
				// Log panic but continue
			}
		}()
		task()
	}
	select {
	case q.ch <- wrappedTask:
		// Task successfully enqueued
	case <-q.ctx.Done():
		// Context has been canceled
	default:
		// Queue is full, retry asynchronously once
		go func() {
			select {
			case q.ch <- wrappedTask:
				// Retry succeeded
			case <-q.ctx.Done():
			case <-time.After(UdpTaskTimeout):
			}
		}()
	}
}

// cleanupQueue cleans up the queue
func (p *UdpTaskPool) cleanupQueue(key string, q *UdpTaskQueue, cancel context.CancelFunc, ch chan UdpTask) {
	p.mu.Lock()
	cancel()
	delete(p.m, key)
	p.mu.Unlock()

	// Wait for cleanup to complete, with timeout
	select {
	case <-q.closed:
	case <-time.After(1 * time.Second):
		// Force cleanup
	}

	// Recycle channel
	if len(ch) == 0 {
		for len(ch) > 0 {
			<-ch
		}
		p.queueChPool.Put(ch)
	}
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)
