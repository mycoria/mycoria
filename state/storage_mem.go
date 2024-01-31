package state

import (
	"net/netip"
	"sync"
	"time"
)

// MemStorage is a simple storage implementation using memory only.
type MemStorage struct {
	entries     map[netip.Addr]*StoredInfo
	entriesLock sync.RWMutex
}

// NewMemStorage returns an empty storage.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		entries: make(map[netip.Addr]*StoredInfo),
	}
}

// Stop does nothing.
func (s *MemStorage) Stop() error {
	return nil
}

// Load returns an entry from the storage.
func (s *MemStorage) Load(ip netip.Addr) *StoredInfo {
	s.entriesLock.RLock()
	defer s.entriesLock.RUnlock()

	// Load entry, return nil if it does not exist.
	info := s.entries[ip]
	if info == nil {
		return nil
	}

	// Update entry and return it.
	now := time.Now()
	info.UsedAt = &now
	return info
}

// Query queries the storage.
func (s *MemStorage) Query(q *StorageQuery) error {
	s.entriesLock.RLock()
	defer s.entriesLock.RUnlock()

	for _, info := range s.entries {
		q.Add(info)
	}
	return nil
}

// Save saves an entry to the storage.
func (s *MemStorage) Save(info *StoredInfo) error {
	s.entriesLock.Lock()
	defer s.entriesLock.Unlock()

	s.entries[info.Address.IP] = info
	return nil
}

// Size returns the current size of the storage.
func (s *MemStorage) Size() int {
	s.entriesLock.Lock()
	defer s.entriesLock.Unlock()

	return len(s.entries)
}

// Prune prunes the storage down to the specified amount of entries.
func (s *MemStorage) Prune(keep int) {
	s.entriesLock.Lock()
	defer s.entriesLock.Unlock()

	// Remove all entries that have been never used.
	for ip, info := range s.entries {
		if info.UsedAt == nil {
			delete(s.entries, ip)
		}
	}
	if len(s.entries) <= keep {
		return
	}

	// Remove old entries.
	oneMonthAgo := time.Now().Add(-30 * 24 * time.Hour)
	for ip, info := range s.entries {
		switch {
		case info.UpdatedAt.Before(oneMonthAgo):
			delete(s.entries, ip)
		case info.UsedAt.Before(oneMonthAgo):
			delete(s.entries, ip)
		}
	}
	if len(s.entries) <= keep {
		return
	}

	// TODO: Add more pruning steps.
}
