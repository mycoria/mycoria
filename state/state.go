package state

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/storage"
)

// State manages and stores states.
type State struct {
	mgr *mgr.Manager

	storage        storage.Storage
	maxStorageSize int

	sessions     map[netip.Addr]*Session
	sessionsLock sync.Mutex

	instance instance
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Identity() *m.Address
	Config() *config.Config
}

const minStorageSize = 10_000

// New returns a new state manager.
func New(instance instance, store storage.Storage) *State {
	// Fallback to memory storage.
	if store == nil {
		store = storage.NewMemStorage()
	}

	// Allow for 100x storage growth.
	maxStorageSize := store.Size() * 100
	// Raise to minimum.
	if maxStorageSize < minStorageSize {
		maxStorageSize = minStorageSize
	}

	return &State{
		storage:        store,
		maxStorageSize: maxStorageSize,

		sessions: make(map[netip.Addr]*Session),
		instance: instance,
	}
}

// Start starts brings the device online and starts workers.
func (state *State) Start(mgr *mgr.Manager) error {
	state.mgr = mgr
	mgr.Go("session cleaner", state.sessionCleanerWorker)
	return nil
}

// Stop closes the interface and stops workers.
func (state *State) Stop(mgr *mgr.Manager) error {
	// Notify workers.
	mgr.Cancel()
	// Wait for all workers.
	mgr.WaitForWorkers(10 * time.Second)

	return nil
}

// AddRouter adds a router to the state manager.
func (state *State) AddRouter(address *m.PublicAddress) error {
	// Check if we already have that router.
	info, err := state.storage.GetRouter(address.IP)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("check existing entry: %w", err)
	}
	if info != nil {
		return nil
	}

	// Otherwise, create a now stored info.
	err = state.storage.SaveRouter(&storage.StoredRouter{
		Address:   address,
		Universe:  state.instance.Config().Router.Universe,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("save to storage: %w", err)
	}

	if state.mgr != nil {
		state.mgr.Info(
			"new router",
			"router", address.IP,
		)
	}
	return nil
}

// QueryRouters query the router storage.
func (state *State) QueryRouters(q *storage.RouterQuery) error {
	return state.storage.QueryRouters(q)
}

// QueryNearestRouters queries the nearest routers to the given IP.
func (state *State) QueryNearestRouters(ip netip.Addr, max int) ([]*storage.StoredRouter, error) {
	q := storage.NewRouterQuery(
		func(a *storage.StoredRouter) bool {
			return !a.Offline &&
				a.PublicInfo != nil &&
				len(a.PublicInfo.IANA) > 0 &&
				len(a.PublicInfo.Listeners) > 0 &&
				a.Universe == state.instance.Config().Router.Universe
		},
		func(a, b *storage.StoredRouter) int {
			aDist := m.IPDistance(ip, a.Address.IP)
			bDist := m.IPDistance(ip, b.Address.IP)
			return aDist.Compare(bDist)
		},
		max,
	)
	if err := state.storage.QueryRouters(q); err != nil {
		return nil, err
	}

	return q.Result(), nil
}

// AddPublicRouterInfo adds the public router info.
func (state *State) AddPublicRouterInfo(id netip.Addr, info *m.RouterInfo) error {
	// Check if we already have that router.
	stored, err := state.storage.GetRouter(id)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("get stored router: %w", err)
	}
	if stored == nil {
		return errors.New("router unknown")
	}
	firstInfo := stored.PublicInfo == nil

	// Add to storage and save.
	stored.PublicInfo = info
	stored.Universe = state.instance.Config().Router.Universe
	stored.UpdatedAt = time.Now()
	stored.Offline = false
	err = state.storage.SaveRouter(stored)
	if err != nil {
		return fmt.Errorf("save to storage: %w", err)
	}

	if state.mgr != nil {
		if firstInfo {
			state.mgr.Info(
				"router info added",
				"router", id,
			)
		} else {
			state.mgr.Debug(
				"router info updated",
				"router", id,
			)
		}
	}
	return nil
}

// MarkRouterOffline marks that the router has announced it is going offline.
func (state *State) MarkRouterOffline(id netip.Addr) error {
	// Check if we already have that router.
	stored, err := state.storage.GetRouter(id)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("get stored router: %w", err)
	}
	if stored == nil {
		return errors.New("router unknown")
	}

	// Add to storage and save.
	stored.Offline = true
	err = state.storage.SaveRouter(stored)
	if err != nil {
		return fmt.Errorf("save to storage: %w", err)
	}

	state.mgr.Debug(
		"router going offline",
		"router", id,
	)
	return nil
}

// SetEncryptionSession sets the encryption session.
func (state *State) SetEncryptionSession(ip netip.Addr, encSession *EncryptionSession) error {
	session := state.GetSession(ip)
	if session == nil {
		return fmt.Errorf("no session for %s", ip)
	}

	session.lock.Lock()
	defer session.lock.Unlock()

	session.encryption = encSession
	return nil
}

// GetSession returns a new session for the given router.
func (state *State) GetSession(ip netip.Addr) *Session {
	state.sessionsLock.Lock()
	defer state.sessionsLock.Unlock()

	// Check for an existing session.
	s := state.sessions[ip]
	if s != nil {
		s.inUse()
		return s
	}

	// Otherwise, create a new one.
	info, err := state.storage.GetRouter(ip)
	if err != nil {
		// Cannot create session without router info.
		// TODO: What to do if the storage is broken?
		return nil
	}

	// Create, save and return session.
	s = &Session{
		id:           ip,
		address:      info.Address,
		lastActivity: time.Now(),
		state:        state,
	}
	state.sessions[s.id] = s
	return s
}

func (state *State) sessionCleanerWorker(w *mgr.WorkerCtx) error {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	var tick int

	for {
		tick++

		select {
		case <-w.Done():
			return nil
		case <-ticker.C:
			// Clean session every tick.
			state.cleanSessions()

			// Clean storage every 10 ticks.
			// TODO: Clean storage in separate worker.
			if tick%10 == 0 {
				state.cleanStorage()
			}
		}
	}
}

func (state *State) cleanSessions() {
	state.sessionsLock.Lock()
	defer state.sessionsLock.Unlock()

	for ip, session := range state.sessions {
		if session.killable() {
			delete(state.sessions, ip)
		}
	}
}

func (state *State) cleanStorage() {
	if state.storage.Size() > state.maxStorageSize {
		state.storage.Prune(state.maxStorageSize)
	}
}
