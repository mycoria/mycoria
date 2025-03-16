package storage

import (
	"errors"
	"net/netip"

	"github.com/mycoria/mycoria/mgr"
)

// Errors.
var (
	ErrNotFound = errors.New("not found")
)

// Storage includes all storage interfaces.
type Storage interface {
	DatabaseModule
	RouterStorage
	DomainMappingStorage
}

// DatabaseModule is an interface to a managed storage backend.
type DatabaseModule interface {
	Start() error
	Stop() error
	Manager() *mgr.Manager
	Size() int
	Prune(keep int)
}

// RouterStorage is an interface to a router storage.
type RouterStorage interface {
	GetRouter(router netip.Addr) (*StoredRouter, error)
	QueryRouters(query *RouterQuery) error
	SaveRouter(router *StoredRouter) error
	DeleteRouter(router netip.Addr) error
}

// DomainMappingStorage is an interface to a domain mapping storage.
type DomainMappingStorage interface {
	GetMapping(domain string) (router netip.Addr, err error)
	QueryMappings(search string) ([]StoredMapping, error)
	SaveMapping(domain string, router netip.Addr) error
	DeleteMapping(domain string) error
}
