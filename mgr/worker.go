package mgr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

// FindPanicsInPackages configures a list of package names (or anything in the
// package path) that will be matched in order to find the source of a panic.
// It is read without synchronization while handling a panic, so it must be set
// once during initialization and not mutated afterwards.
var FindPanicsInPackages []string

// ErrWorkerPanic wraps every error produced by a recovered worker panic, so a
// panic can be identified with errors.Is regardless of the panic value's text.
var ErrWorkerPanic = errors.New("panic")

// workerContextKey is a key used for the context key/value storage.
type workerContextKey struct{}

// WorkerCtxContextKey is the key used to add the WorkerCtx to a context.
var WorkerCtxContextKey = workerContextKey{}

// WorkerCtx provides workers with the necessary environment for flow control
// and logging.
type WorkerCtx struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	logger *slog.Logger
}

// AddToCtx adds the WorkerCtx to the given context.
func (w *WorkerCtx) AddToCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, WorkerCtxContextKey, w)
}

// WorkerFromCtx returns the WorkerCtx from the given context.
func WorkerFromCtx(ctx context.Context) *WorkerCtx {
	v := ctx.Value(WorkerCtxContextKey)
	if w, ok := v.(*WorkerCtx); ok {
		return w
	}
	return nil
}

// Ctx returns the worker context.
// Is automatically canceled after the worker stops/returns, regardless of error.
func (w *WorkerCtx) Ctx() context.Context {
	return w.ctx
}

// Cancel cancels the worker context.
// Is automatically called after the worker stops/returns, regardless of error.
func (w *WorkerCtx) Cancel() {
	w.cancelCtx()
}

// Done returns the context Done channel.
func (w *WorkerCtx) Done() <-chan struct{} {
	return w.ctx.Done()
}

// IsDone checks whether the worker context is done.
func (w *WorkerCtx) IsDone() bool {
	return w.ctx.Err() != nil
}

// Logger returns the logger used by the worker context.
func (w *WorkerCtx) Logger() *slog.Logger {
	return w.logger
}

// LogEnabled reports whether the logger emits log records at the given level.
// The worker context is automatically supplied.
func (w *WorkerCtx) LogEnabled(level slog.Level) bool {
	return w.logger.Enabled(w.ctx, level)
}

// Debug logs at LevelDebug.
// The worker context is automatically supplied.
func (w *WorkerCtx) Debug(msg string, args ...any) { w.log(slog.LevelDebug, msg, args...) }

// Info logs at LevelInfo.
// The worker context is automatically supplied.
func (w *WorkerCtx) Info(msg string, args ...any) { w.log(slog.LevelInfo, msg, args...) }

// Warn logs at LevelWarn.
// The worker context is automatically supplied.
func (w *WorkerCtx) Warn(msg string, args ...any) { w.log(slog.LevelWarn, msg, args...) }

// Error logs at LevelError.
// The worker context is automatically supplied.
func (w *WorkerCtx) Error(msg string, args ...any) { w.log(slog.LevelError, msg, args...) }

// Log emits a log record with the current time and the given level and message.
// The worker context is automatically supplied.
func (w *WorkerCtx) Log(level slog.Level, msg string, args ...any) { w.log(level, msg, args...) }

// LogAttrs is a more efficient version of Log() that accepts only Attrs.
// The worker context is automatically supplied.
func (w *WorkerCtx) LogAttrs(level slog.Level, msg string, attrs ...slog.Attr) {
	w.logAttrs(level, msg, attrs...)
}

// log builds the record so source= points at the caller of the exported method
// rather than at this wrapper. Mirrors slog.Logger.log minus its fixed skip.
func (w *WorkerCtx) log(level slog.Level, msg string, args ...any) {
	if !w.logger.Enabled(w.ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, callerPC())
	r.Add(args...)
	_ = w.logger.Handler().Handle(w.ctx, r)
}

func (w *WorkerCtx) logAttrs(level slog.Level, msg string, attrs ...slog.Attr) {
	if !w.logger.Enabled(w.ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, callerPC())
	r.AddAttrs(attrs...)
	_ = w.logger.Handler().Handle(w.ctx, r)
}

// LogAttrsAt logs at the given level with source taken from pc (e.g. a value from
// runtime.Callers), for helpers logging on behalf of a caller further up the stack.
// A nil ctx uses the worker context.
func (w *WorkerCtx) LogAttrsAt(ctx context.Context, pc uintptr, level slog.Level, msg string, attrs ...slog.Attr) {
	if ctx == nil {
		ctx = w.ctx
	}
	if !w.logger.Enabled(ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, pc)
	r.AddAttrs(attrs...)
	_ = w.logger.Handler().Handle(ctx, r)
}

// Go starts the given function in a goroutine (as a "worker").
// The worker context has
// - A separate context which is canceled when the functions returns.
// - Access to named structure logging.
// - Given function is re-run after failure (with backoff).
// - Panic catching.
// - Flow control helpers.
func (m *Manager) Go(name string, fn func(w *WorkerCtx) error) {
	go m.manageWorker(name, fn)
}

func (m *Manager) manageWorker(name string, fn func(w *WorkerCtx) error) {
	m.workerStart()
	defer m.workerDone()

	w := &WorkerCtx{
		logger: m.logger.With("worker", name),
	}

	backoff := time.Second
	failCnt := 0

	for {
		panicInfo, err := m.runWorker(w, fn)
		switch {
		case err == nil:
			// No error means that the worker is finished.
			return

		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// A canceled context or dexceeded eadline also means that the worker is finished.
			return

		default:
			// Any other errors triggers a restart with backoff.

			// If manager is stopping, just log error and return.
			if m.IsDone() {
				if panicInfo != "" {
					m.Error(
						"worker failed",
						"err", err,
						"file", panicInfo,
					)
				} else {
					m.Error(
						"worker failed",
						"err", err,
					)
				}
				return
			}

			// Count failure and increase backoff (up to limit),
			failCnt++
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}

			// Log error and retry after backoff duration.
			if panicInfo != "" {
				m.Error(
					"worker failed",
					"failCnt", failCnt,
					"backoff", backoff,
					"err", err,
					"file", panicInfo,
				)
			} else {
				m.Error(
					"worker failed",
					"failCnt", failCnt,
					"backoff", backoff,
					"err", err,
				)
			}

			// Report error as alert.
			m.reportWorkerError(name, panicInfo, err)

			select {
			case <-time.After(backoff):
			case <-m.ctx.Done():
				return
			}
		}
	}
}

// Do directly executes the given function (as a "worker").
// The worker context has
// - A separate context which is canceled when the functions returns.
// - Access to named structure logging.
// - Given function is NOT re-run when it fails.
// - Panic catching.
// - Flow control helpers.
func (m *Manager) Do(name string, fn func(w *WorkerCtx) error) error {
	m.workerStart()
	defer m.workerDone()

	// Create context.
	w := &WorkerCtx{
		logger: m.logger.With("worker", name),
	}

	// Run worker.
	panicInfo, err := m.runWorker(w, fn)
	switch {
	case err == nil:
		// No error means that the worker is finished.
		return nil

	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// A canceled context or dexceeded eadline also means that the worker is finished.
		return err

	default:
		// Log error and return.
		if panicInfo != "" {
			m.Error(
				"worker failed",
				"err", err,
				"file", panicInfo,
			)
		} else {
			m.Error(
				"worker failed",
				"err", err,
			)
		}

		// Report error as alert.
		m.reportWorkerError(name, panicInfo, err)

		return err
	}
}

// reportWorkerError reports a failed or panicked worker to the configured worker
// error alert manager, if one is set. Panics are identified via
// errors.Is(err, ErrWorkerPanic) and reported as critical panic alerts, with
// panicInfo (the extracted panic source, which may be empty if none was found)
// attached as the alert data; all other errors are reported as error alerts.
// Alerts are keyed by error kind and worker name ("worker-panic: <name>" or
// "worker-error: <name>"), so repeated failures of the same kind update a single
// alert rather than accumulating; a worker that both panics and errors produces
// two distinct alerts.
func (m *Manager) reportWorkerError(name, panicInfo string, err error) {
	alertMgr := m.GetWorkerErrorMgr()
	if alertMgr == nil {
		return
	}

	if errors.Is(err, ErrWorkerPanic) {
		alertMgr.Report(Alert{
			ID:            "worker-panic: " + name,
			Name:          "Worker Panic: " + name,
			Message:       fmt.Sprintf("Worker %s panicked: %v", name, err),
			Severity:      AlertSeverityCritical,
			ReportedAt:    time.Now(),
			AlertDataType: "text",
			AlertData:     panicInfo,
		})
	} else {
		alertMgr.Report(Alert{
			ID:         "worker-error: " + name,
			Name:       "Worker Error: " + name,
			Message:    fmt.Sprintf("Worker %s failed: %v", name, err),
			Severity:   AlertSeverityError,
			ReportedAt: time.Now(),
		})
	}
}

func (m *Manager) runWorker(w *WorkerCtx, fn func(w *WorkerCtx) error) (panicInfo string, err error) {
	// Create worker context that is canceled when worker finished or dies.
	w.ctx, w.cancelCtx = context.WithCancel(m.Ctx())
	defer w.Cancel()

	// Recover from panic.
	defer func() {
		panicVal := recover()
		if panicVal != nil {
			// Preserve the original error in the chain (errors.Is/As) when the
			// panic value is itself an error; otherwise format it as a value.
			if panicErr, ok := panicVal.(error); ok {
				err = fmt.Errorf("%w: %w", ErrWorkerPanic, panicErr)
			} else {
				err = fmt.Errorf("%w: %v", ErrWorkerPanic, panicVal)
			}

			// Print panic to stderr.
			stackTrace := string(debug.Stack())
			fmt.Fprintf(
				os.Stderr,
				"===== PANIC =====\n%v\n\n%s=====  END  =====\n",
				panicVal,
				stackTrace,
			)

			// Find the line in the stack trace that refers to where the panic occurred.
			stackLines := strings.Split(stackTrace, "\n")
			foundPanic := false
		findPanicSource:
			for i, line := range stackLines {
				if !foundPanic {
					if strings.Contains(line, "panic(") {
						foundPanic = true
					}
				} else {
					if strings.Contains(line, "mycoria") {
						if i+1 < len(stackLines) {
							panicInfo = strings.SplitN(strings.TrimSpace(stackLines[i+1]), " ", 2)[0]
						}
						break
					} else if len(FindPanicsInPackages) > 0 {
						for _, pkg := range FindPanicsInPackages {
							if strings.Contains(line, pkg) {
								if i+1 < len(stackLines) {
									panicInfo = strings.SplitN(strings.TrimSpace(stackLines[i+1]), " ", 2)[0]
								}
								break findPanicSource
							}
						}
					}
				}
			}
		}
	}()

	err = fn(w)
	return //nolint
}
