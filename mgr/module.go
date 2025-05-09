package mgr

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Group describes a group of modules.
type Group struct {
	modules []*groupModule

	ctx       context.Context
	cancelCtx context.CancelFunc
	ctxLock   sync.Mutex
}

type groupModule struct {
	module Module
	mgr    *Manager
}

// Module is an manage-able instance of some component.
type Module interface {
	Manager() *Manager
	Start() error
	Stop() error
}

// NewGroup returns a new group of modules.
func NewGroup(modules ...Module) *Group {
	// Create group.
	g := &Group{
		modules: make([]*groupModule, 0, len(modules)),
	}
	g.initGroupContext()

	// Initialize groups modules.
	for _, m := range modules {
		mgr := m.Manager()

		// Skip non-values.
		switch {
		case m == nil:
			// Skip nil values to allow for cleaner code.
			continue
		case reflect.ValueOf(m).IsNil():
			// If nil values are given via a struct, they are will be interfaces to a
			// nil type. Ignore these too.
			continue
		case mgr == nil:
			// Skip modules without manager.
			continue
		case mgr.name == "":
			// Set fallback module name.
			mgr.name = makeModuleName(m)
		}

		// Add module to group.
		g.modules = append(g.modules, &groupModule{
			module: m,
			mgr:    mgr,
		})
	}

	return g
}

// Start starts all modules in the group in the defined order.
// If a module fails to start, itself and all previous modules
// will be stopped in the reverse order.
func (g *Group) Start() error {
	g.initGroupContext()

	for i, m := range g.modules {
		err := m.module.Start()
		if err != nil {
			g.stopFrom(i)
			return fmt.Errorf("failed to start %s: %w", makeModuleName(m.module), err)
		}
		m.mgr.Info("started")
	}
	return nil
}

// Stop stops all modules in the group in the reverse order.
func (g *Group) Stop() (ok bool) {
	return g.stopFrom(len(g.modules) - 1)
}

func (g *Group) stopFrom(index int) (ok bool) {
	ok = true
	for i := index; i >= 0; i-- {
		m := g.modules[i]
		err := m.module.Stop()
		if err != nil {
			m.mgr.Error("failed to stop", "err", err)
			ok = false
		}
		m.mgr.Cancel()
		if m.mgr.WaitForWorkers(0) {
			m.mgr.Info("stopped")
		} else {
			ok = false
			m.mgr.Error(
				"failed to stop",
				"err", "timed out",
				"workerCnt", m.mgr.workerCnt.Load(),
			)
		}
	}

	g.stopGroupContext()
	return
}

func (g *Group) initGroupContext() {
	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()

	g.ctx, g.cancelCtx = context.WithCancel(context.Background())
}

func (g *Group) stopGroupContext() {
	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()

	g.cancelCtx()
}

// Done returns the context Done channel.
func (g *Group) Done() <-chan struct{} {
	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()

	return g.ctx.Done()
}

// IsDone checks whether the manager context is done.
func (g *Group) IsDone() bool {
	g.ctxLock.Lock()
	defer g.ctxLock.Unlock()

	return g.ctx.Err() != nil
}

// GetAlerts returns the reported alerts of all alerting group modules.
func (g *Group) GetAlerts() []AlertUpdate {
	updates := make([]AlertUpdate, 0, len(g.modules))
	for _, gm := range g.modules {
		if alertMgr, ok := gm.module.(AlertingModule); ok {
			updates = append(updates, alertMgr.Alerts().Export())
		}
	}
	return updates
}

// AddAlertsCallback adds the given callback function to all alerting group modules.
func (g *Group) AddAlertsCallback(callbackName string, callback EventCallbackFunc[AlertUpdate]) {
	for _, gm := range g.modules {
		if alertMgr, ok := gm.module.(AlertingModule); ok {
			alertMgr.Alerts().AddCallback(callbackName, callback)
		}
	}
}

// RunModules is a simple wrapper function to start modules and stop them again
// when the given context is canceled.
func RunModules(ctx context.Context, modules ...Module) error {
	g := NewGroup(modules...)

	// Start module.
	if err := g.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	// Stop module when context is canceled.
	<-ctx.Done()
	if !g.Stop() {
		return errors.New("failed to stop")
	}

	return nil
}

func makeModuleName(m Module) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", m), "*")
}
