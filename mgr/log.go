package mgr

import "runtime"

// callerPC returns the program counter `skip` frames above runtime.Callers,
// suitable for slog.NewRecord. Called from a one-line logging wrapper the frames
// are: 0=runtime.Callers, 1=callerPC, 2=the log/logAttrs helper, 3=the exported
// method, 4=the real caller — so the exported methods pass callerPC(4).
func callerPC(skip int) uintptr {
	var pcs [1]uintptr
	runtime.Callers(skip, pcs[:])
	return pcs[0]
}
