// Copyright © 2026 Irisity AB
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"context"
	"time"

	"github.com/pkg/errors"
)

// ErrLoginEventQueueFull is logged when a login event is dropped because every
// worker is busy and the queue is full.
var ErrLoginEventQueueFull = errors.New("the login event queue is full")

type (
	// LoginEventDispatcher runs login event deliveries on a fixed number of
	// workers that take jobs from a queue of fixed size. It keeps the
	// goroutines and the memory that notifications use bounded, however many
	// logins arrive and however slow the receiver is.
	//
	// The workers run until the process exits. Queued jobs are lost when it
	// does, as delivery is best effort.
	LoginEventDispatcher struct {
		queue   chan loginEventJob
		timeout time.Duration
	}

	// LoginEventDispatcherProvider returns the dispatcher that every login
	// notification hook shares.
	LoginEventDispatcherProvider interface {
		LoginEventDispatcher(ctx context.Context) *LoginEventDispatcher
	}

	loginEventJob struct {
		// ctx carries the request's values without its cancellation.
		ctx     context.Context
		deliver func(ctx context.Context)
	}
)

// NewLoginEventDispatcher starts workers goroutines that run up to queueSize
// queued deliveries. Each delivery runs under a two-minute timeout.
func NewLoginEventDispatcher(workers, queueSize int) *LoginEventDispatcher {
	return newLoginEventDispatcher(workers, queueSize, loginEventTimeout)
}

func newLoginEventDispatcher(workers, queueSize int, timeout time.Duration) *LoginEventDispatcher {
	workers = max(workers, 1)
	queueSize = max(queueSize, 1)

	d := &LoginEventDispatcher{
		queue:   make(chan loginEventJob, queueSize),
		timeout: timeout,
	}
	for i := 0; i < workers; i++ {
		go d.work()
	}
	return d
}

// Enqueue queues deliver and returns right away. deliver runs on a worker with
// the values of ctx, without its cancellation, and with the delivery timeout,
// which starts when a worker takes the job. Enqueue returns false and drops
// the job if the queue is full.
func (d *LoginEventDispatcher) Enqueue(ctx context.Context, deliver func(ctx context.Context)) bool {
	select {
	case d.queue <- loginEventJob{ctx: context.WithoutCancel(ctx), deliver: deliver}:
		return true
	default:
		return false
	}
}

func (d *LoginEventDispatcher) work() {
	for job := range d.queue {
		d.run(job)
	}
}

func (d *LoginEventDispatcher) run(job loginEventJob) {
	ctx, cancel := context.WithTimeout(job.ctx, d.timeout)
	defer cancel()
	job.deliver(ctx)
}
