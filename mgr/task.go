package mgr

import (
	"sync"
	"time"
)

// Task manages a worker.
type Task struct {
	mgr  *Manager
	name string
	fn   func(w *WorkerCtx) error

	run    bool
	delay  time.Duration
	repeat time.Duration
	lock   sync.Mutex

	eval chan struct{}
}

// NewTask creates a new task, but does not yet execute or schedule anything.
func (m *Manager) NewTask(name string, fn func(w *WorkerCtx) error) *Task {
	return m.newTask(name, fn, 0, 0)
}

// Delay creates a new task and immediately schedules a delayed execution.
func (m *Manager) Delay(name string, duration time.Duration, fn func(w *WorkerCtx) error) *Task {
	return m.newTask(name, fn, duration, 0)
}

// Repeat creates a new task and immediately schedules a repeated execution.
func (m *Manager) Repeat(name string, interval time.Duration, fn func(w *WorkerCtx) error) *Task {
	return m.newTask(name, fn, 0, interval)
}

func (m *Manager) newTask(
	name string,
	fn func(w *WorkerCtx) error,
	delay, repeat time.Duration,
) *Task {
	// Create Task.
	t := &Task{
		mgr:    m,
		name:   name,
		delay:  delay,
		repeat: repeat,
		fn:     fn,
		eval:   make(chan struct{}, 1),
	}

	// Start task manager worker and return.
	go t.taskMgr()
	return t
}

func (t *Task) taskMgr() {
	var (
		wait   bool
		run    bool
		delay  time.Duration
		repeat time.Duration
	)

start:
	for {
		// Check if we are done.
		if t.mgr.IsDone() {
			return
		}

		// Wait until there is something to do.
		if wait {
			select {
			case <-t.eval:
				// Do something!
			case <-t.mgr.ctx.Done():
				return
			}
			wait = false
		}

		// Get current configuration.
		t.lock.Lock()
		run = t.run
		delay = t.delay
		repeat = t.repeat
		t.lock.Unlock()

		// Execute worker.
		if run {
			// Mark as completed.
			t.lock.Lock()
			t.run = false
			t.lock.Unlock()

			// Execute and ignore error - it is already being logged.
			_ = t.mgr.Do(t.name, t.fn)

			continue start
		}

		// Delayed execution.
		if delay > 0 {
			select {
			case <-time.After(delay):
				// Mark as completed.
				t.lock.Lock()
				t.delay = 0
				t.lock.Unlock()

				// Execute and ignore error - it is already being logged.
				_ = t.mgr.Do(t.name, t.fn)

			case <-t.eval:
				// Re-evaluate.

			case <-t.mgr.Done():
				// Stop when manager is canceled.
				return
			}

			continue start
		}

		// Repeat worker.
		if repeat > 0 {
			ticker := time.NewTicker(repeat)
			select {
			case <-ticker.C:
				// Execute and ignore error - it is already being logged.
				_ = t.mgr.Do(t.name, t.fn)

			case <-t.eval:
				// Re-evaluate.

			case <-t.mgr.Done():
				// Stop when manager is canceled.
				return
			}

			continue start
		}

		wait = true
	}
}

func (t *Task) notify() {
	select {
	case t.eval <- struct{}{}:
	default:
	}
}

// Go immediately executes the task.
func (t *Task) Go() *Task {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.run = true
	t.notify()

	return t
}

// Repeat repeats the task at the given interval.
func (t *Task) Repeat(interval time.Duration) *Task {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.repeat = interval
	t.notify()

	return t
}

// Delay executes the task after the given duration.
func (t *Task) Delay(duration time.Duration) *Task {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.delay = duration
	t.notify()

	return t
}
