package mgr

import "runtime"

// callerPC returns the program counter of the caller of an exported logging
// method, suitable for slog.NewRecord. The frames above runtime.Callers are:
// 0=runtime.Callers, 1=callerPC, 2=the log/logAttrs helper, 3=the exported method,
// 4=the real caller — hence the fixed skip of 4.
func callerPC() uintptr {
	var pcs [1]uintptr
	runtime.Callers(4, pcs[:])
	return pcs[0]
}
