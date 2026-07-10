package mgr

import (
	"context"
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
// resolved source location of the (single) record emitted. The manager must be
// constructed inside emit so its logger picks up the capture handler.
func captureSource(t *testing.T, emit func()) (file string, line int) {
	t.Helper()
	h := &sourceCaptureHandler{fn: func(r slog.Record) {
		f, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		file, line = f.File, f.Line
	}}
	defer func(old *slog.Logger) { slog.SetDefault(old) }(slog.Default())
	slog.SetDefault(slog.New(h))
	emit()
	return file, line
}

func TestManagerLogSource(t *testing.T) {
	file, _ := captureSource(t, func() {
		m := New("test")
		m.Error("boom")
	})
	if !strings.HasSuffix(file, "manager_test.go") {
		t.Fatalf("source file = %q, want the caller (manager_test.go), not the mgr wrapper", file)
	}
}

func TestWorkerCtxLogSource(t *testing.T) {
	file, _ := captureSource(t, func() {
		m := New("test")
		_ = m.Do("t", func(w *WorkerCtx) error { w.Error("boom"); return nil })
	})
	if !strings.HasSuffix(file, "manager_test.go") {
		t.Fatalf("source file = %q, want the caller (manager_test.go), not the mgr wrapper", file)
	}
}
