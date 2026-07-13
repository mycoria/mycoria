package mgr

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

// sourceCaptureHandler routes every record to fn. Its With* methods return the
// receiver so the captured source PC survives the slog.Default().With(...) calls
// inside newManager and Manager.Do.
type sourceCaptureHandler struct{ fn func(slog.Record) }

func (h *sourceCaptureHandler) Enabled(context.Context, slog.Level) bool      { return true }
func (h *sourceCaptureHandler) Handle(_ context.Context, r slog.Record) error { h.fn(r); return nil }
func (h *sourceCaptureHandler) WithAttrs([]slog.Attr) slog.Handler            { return h }
func (h *sourceCaptureHandler) WithGroup(string) slog.Handler                 { return h }

// captureSource installs a capturing default logger, runs emit, and returns the
// resolved source file of the (single) record emitted. The manager must be
// constructed inside emit so its logger picks up the capture handler.
func captureSource(t *testing.T, emit func()) (file string) {
	t.Helper()
	h := &sourceCaptureHandler{fn: func(r slog.Record) {
		f, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		file = f.File
	}}
	defer func(old *slog.Logger) { slog.SetDefault(old) }(slog.Default())
	slog.SetDefault(slog.New(h))
	emit()
	return file
}

func TestManagerLogSource(t *testing.T) {
	file := captureSource(t, func() {
		m := New("test")
		m.Error("boom")
	})
	if !strings.HasSuffix(file, "manager_test.go") {
		t.Fatalf("source file = %q, want the caller (manager_test.go), not the mgr wrapper", file)
	}
}

func TestWorkerCtxLogSource(t *testing.T) {
	file := captureSource(t, func() {
		m := New("test")
		_ = m.Do("t", func(w *WorkerCtx) error { w.Error("boom"); return nil })
	})
	if !strings.HasSuffix(file, "manager_test.go") {
		t.Fatalf("source file = %q, want the caller (manager_test.go), not the mgr wrapper", file)
	}
}

// TestDoPanicWithContextErrorIsReported ensures a worker that panics with a value
// that is (or wraps) a context error is still treated as a failure and reported,
// rather than being misclassified as a normal cancellation. Regression test for the
// %w panic wrapping interacting with the errors.Is(context.Canceled) checks in Do.
func TestDoPanicWithContextErrorIsReported(t *testing.T) {
	m := New("test")
	alertMgr := NewAlertMgr(m) // auto-registers as the manager's worker error alert manager

	err := m.Do("panicky", func(w *WorkerCtx) error {
		panic(context.Canceled)
	})

	if !errors.Is(err, ErrWorkerPanic) {
		t.Fatalf("err = %v, want it to wrap ErrWorkerPanic", err)
	}
	alerts := alertMgr.Export().Alerts
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (a panic must be reported, not treated as cancellation)", len(alerts))
	}
	if got, want := alerts[0].ID, "worker-panic: panicky"; got != want {
		t.Errorf("alert ID = %q, want %q", got, want)
	}
	if got, want := alerts[0].Severity, AlertSeverityCritical; got != want {
		t.Errorf("alert severity = %q, want %q", got, want)
	}
}
