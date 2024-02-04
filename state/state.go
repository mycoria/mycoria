package state

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

// State manages and stores states.
type State struct {
	mgr *mgr.Manager

	storage        Storage
	maxStorageSize int

	sessions     map[netip.Addr]*Session
	sessionsLock sync.Mutex

	instance instance
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Identity() *m.Address
}

const minStorageSize = 10_000

// New returns a new state manager.
func New(instance instance, storage Storage) *State {
	// Fallback to memory storage.
	if storage == nil {
		storage = NewMemStorage()
	}

	// Allow for 100x storage growth.
	maxStorageSize := storage.Size() * 100
	// Raise to minimum.
	if maxStorageSize < minStorageSize {
		maxStorageSize = minStorageSize
	}

	return &State{
		storage:        storage,
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
	// Shutdown storage.
	return state.storage.Stop()
}

// AddRouter adds a router to the state manager.
func (state *State) AddRouter(address *m.PublicAddress) error {
	// Check if we already have that router.
	info := state.storage.Load(address.IP)
	if info != nil {
		return nil
	}

	// Otherwise, create a now stored info.
	err := state.storage.Save(&StoredInfo{
		Address:   address,
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
func (state *State) QueryRouters(q *StorageQuery) error {
	return state.storage.Query(q)
}

// QueryNearestRouters queries the nearest routers to the given IP.
func (state *State) QueryNearestRouters(ip netip.Addr, max int) ([]*StoredInfo, error) {
	q := NewQuery(
		func(a *StoredInfo) bool {
			return a.PublicInfo != nil &&
				len(a.PublicInfo.IANA) > 0 &&
				len(a.PublicInfo.Listeners) > 0
		},
		func(a, b *StoredInfo) int {
			aDist := m.IPDistance(ip, a.Address.IP)
			bDist := m.IPDistance(ip, b.Address.IP)
			return aDist.Compare(bDist)
		},
		max,
	)
	if err := state.storage.Query(q); err != nil {
		return nil, err
	}

	return q.Result(), nil
}

// AddPublicRouterInfo adds the public router info.
func (state *State) AddPublicRouterInfo(id netip.Addr, info *m.RouterInfo) error {
	// Check if we already have that router.
	stored := state.storage.Load(id)
	if stored == nil {
		return errors.New("router unknown")
	}

	// Add to storage and save.
	stored.PublicInfo = info
	stored.UpdatedAt = time.Now()
	err := state.storage.Save(stored)
	if err != nil {
		return fmt.Errorf("save to storage: %w", err)
	}

	if state.mgr != nil {
		state.mgr.Info(
			"router info updated",
			"router", id,
		)
	}
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
	info := state.storage.Load(ip)
	if info == nil {
		// Cannot create session without router info.
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
