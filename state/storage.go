package state

import (
	"net/netip"
	"time"

	"github.com/mycoria/mycoria/m"
)

// StoredInfo is the format used to store router information.
type StoredInfo struct {
	Address    *m.PublicAddress `json:"address,omitempty"    yaml:"address,omitempty"`
	PublicInfo *m.RouterInfo    `json:"publicInfo,omitempty" yaml:"publicInfo,omitempty"`

	CreatedAt time.Time  `json:"createdAt,omitempty" yaml:"createdAt,omitempty"`
	UpdatedAt time.Time  `json:"updatedAt,omitempty" yaml:"updatedAt,omitempty"`
	UsedAt    *time.Time `json:"usedAt,omitempty"    yaml:"usedAt,omitempty"`
}

// Storage is an interface to a router info storage.
type Storage interface {
	Load(netip.Addr) *StoredInfo
	Query(*StorageQuery) error
	Save(*StoredInfo) error
	Size() int
	Prune(keep int)
	Stop() error
}
