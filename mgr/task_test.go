package mgr

import (
	"sync/atomic"
	"testing"
	"time"
)

func conditionMetWithin(target time.Duration, tolerance float64, condition func() bool) bool {
	start := time.Now()
	absoluteTolerance := time.Duration(float64(target) * tolerance)
	lowerBound := target - absoluteTolerance
	upperBound := target + absoluteTolerance

	for !condition() {
		if time.Since(start) > upperBound {
			return false
		}
		time.Sleep(1 * time.Millisecond) // Fixed check interval
	}
	elapsed := time.Since(start)
	return elapsed >= lowerBound && elapsed <= upperBound
}

func TestTaskDelay(t *testing.T) {
	t.Parallel()

	m := New("DelayTest")
	value := atomic.Bool{}
	value.Store(false)

	// Create a task that will execute after 1 second.
	m.NewTask("test", func(w *WorkerCtx) error {
		value.Store(true)
		return nil
	}).Delay(1 * time.Second)

	// Check if value is set after 1 second with a 10% tolerance.
	if !conditionMetWithin(1*time.Second, 0.1, value.Load) {
		t.Errorf("task did not execute within the expected delay")
	}
}

func TestTaskRepeat(t *testing.T) {
	t.Parallel()

	m := New("RepeatTest")
	value := atomic.Bool{}
	value.Store(false)

	// Create a task that should repeat every 100 milliseconds.
	m.NewTask("test", func(w *WorkerCtx) error {
		value.Store(true)
		return nil
	}).Repeat(100 * time.Millisecond)

	// Check 10 consecutive executions within 100 milliseconds with a 20% tolerance.
	for i := range 10 {
		if !conditionMetWithin(100*time.Millisecond, 0.2, value.Load) {
			t.Errorf("task did not repeat within the expected interval (iteration %d)", i+1)
			return
		}
		value.Store(false) // Reset value for the next iteration
	}
}

func TestTaskDelayAndRepeat(t *testing.T) {
	t.Parallel()

	m := New("DelayAndRepeatTest")
	value := atomic.Bool{}
	value.Store(false)

	// Create a task that should delay for 1 second and then repeat every 100 milliseconds.
	m.NewTask("test", func(w *WorkerCtx) error {
		value.Store(true)
		return nil
	}).Delay(1 * time.Second).Repeat(100 * time.Millisecond)

	// Check initial delay of 1 second with a 10% tolerance.
	if !conditionMetWithin(1*time.Second, 0.1, value.Load) {
		t.Errorf("task did not delay for the expected duration")
	}

	// Reset value and check 10 consecutive repetitions within 100 milliseconds each with a 20% tolerance.
	value.Store(false)
	for i := range 10 {
		if !conditionMetWithin(100*time.Millisecond, 0.2, value.Load) {
			t.Errorf("task did not repeat within the expected interval (iteration %d)", i+1)
			return
		}
		value.Store(false) // Reset value for the next iteration
	}
}

func TestTaskRepeatAndDelay(t *testing.T) {
	t.Parallel()

	m := New("RepeatAndDelayTest")
	value := atomic.Bool{}
	value.Store(false)

	// Create a task that should repeat every 100 milliseconds and delay for 1 second.
	m.NewTask("test", func(w *WorkerCtx) error {
		value.Store(true)
		return nil
	}).Repeat(100 * time.Millisecond).Delay(1 * time.Second)

	// Check initial delay of 1 second with a 10% tolerance.
	if !conditionMetWithin(1*time.Second, 0.1, value.Load) {
		t.Errorf("task did not delay for the expected duration")
	}

	// Reset value and check 10 consecutive repetitions within 100 milliseconds each with a 20% tolerance.
	value.Store(false)
	for i := range 10 {
		if !conditionMetWithin(100*time.Millisecond, 0.2, value.Load) {
			t.Errorf("task did not repeat within the expected interval (iteration %d)", i+1)
			return
		}
		value.Store(false) // Reset value for the next iteration
	}
}
