package storage

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mycoria/mycoria/mgr"
)

// MemStorage is a simple storage implementation using memory only.
type MemStorage struct {
	routers     map[netip.Addr]*StoredRouter
	routersLock sync.RWMutex

	mappings     map[string]StoredMapping
	mappingsLock sync.RWMutex
}

// NewMemStorage returns an empty storage.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		routers:  make(map[netip.Addr]*StoredRouter),
		mappings: make(map[string]StoredMapping),
	}
}

// Start does nothing.
func (s *MemStorage) Start(*mgr.Manager) error {
	return nil
}

// Stop does nothing.
func (s *MemStorage) Stop(*mgr.Manager) error {
	return nil
}

// GetRouter returns a router from the storage.
func (s *MemStorage) GetRouter(ip netip.Addr) (*StoredRouter, error) {
	s.routersLock.RLock()
	defer s.routersLock.RUnlock()

	// Load entry, return nil if it does not exist.
	info := s.routers[ip]
	if info == nil {
		return nil, ErrNotFound
	}

	// Update entry and return it.
	now := time.Now()
	info.UsedAt = &now
	return info, nil
}

// QueryRouters queries the router storage.
func (s *MemStorage) QueryRouters(q *RouterQuery) error {
	s.routersLock.RLock()
	defer s.routersLock.RUnlock()

	for _, info := range s.routers {
		q.Add(info)
	}
	return nil
}

// SaveRouter saves a router to the storage.
func (s *MemStorage) SaveRouter(info *StoredRouter) error {
	s.routersLock.Lock()
	defer s.routersLock.Unlock()

	info.UpdatedAt = time.Now()
	s.routers[info.Address.IP] = info
	return nil
}

// DeleteRouter deletes a router from the storage.
func (s *MemStorage) DeleteRouter(ip netip.Addr) error {
	s.routersLock.Lock()
	defer s.routersLock.Unlock()

	delete(s.routers, ip)
	return nil
}

// Size returns the current size of the storage.
func (s *MemStorage) Size() int {
	var size int

	func() {
		s.routersLock.Lock()
		defer s.routersLock.Unlock()
		size += len(s.routers)
	}()

	func() {
		s.mappingsLock.Lock()
		defer s.mappingsLock.Unlock()
		size += len(s.mappings)
	}()

	return size
}

// Prune prunes the storage down to the specified amount of entries.
func (s *MemStorage) Prune(keep int) {
	s.routersLock.Lock()
	defer s.routersLock.Unlock()

	// Remove all entries that have been never used.
	for ip, info := range s.routers {
		if info.UsedAt == nil {
			delete(s.routers, ip)
		}
	}
	if len(s.routers) <= keep {
		return
	}

	// Remove old entries.
	oneMonthAgo := time.Now().Add(-30 * 24 * time.Hour)
	for ip, info := range s.routers {
		switch {
		case info.UpdatedAt.Before(oneMonthAgo):
			delete(s.routers, ip)
		case info.UsedAt.Before(oneMonthAgo):
			delete(s.routers, ip)
		}
	}
	if len(s.routers) <= keep {
		return
	}

	// TODO: Add more pruning steps.
}

// GetMapping returns a domain mapping from the storage.
func (s *MemStorage) GetMapping(domain string) (router netip.Addr, err error) {
	s.mappingsLock.RLock()
	defer s.mappingsLock.RUnlock()

	mapping, ok := s.mappings[domain]
	if !ok {
		return netip.Addr{}, ErrNotFound
	}
	return mapping.Router, nil
}

// QueryMappings queries the domain mappings with the given pattern.
func (s *MemStorage) QueryMappings(search string) ([]StoredMapping, error) {
	s.mappingsLock.RLock()
	defer s.mappingsLock.RUnlock()

	result := make([]StoredMapping, 0, 16)
	for domain, mapping := range s.mappings {
		if strings.Contains(domain, search) {
			result = append(result, mapping)
		}
	}

	slices.SortFunc[[]StoredMapping, StoredMapping](result, func(a, b StoredMapping) int {
		return strings.Compare(a.Domain, b.Domain)
	})

	return result, nil
}

// SaveMapping saves a domain mapping to the storage.
func (s *MemStorage) SaveMapping(domain string, router netip.Addr) error {
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()

	mapping := StoredMapping{
		Domain:  domain,
		Router:  router,
		Created: time.Now().UTC(),
	}
	s.mappings[domain] = mapping

	return nil
}

// DeleteMapping deletes a domain mapping from the storage.
func (s *MemStorage) DeleteMapping(domain string) error {
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()

	delete(s.mappings, domain)

	return nil
}
