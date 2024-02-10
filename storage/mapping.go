package storage

import (
	"net/netip"
	"time"
)

// StoredMapping is the format used to store domain mappings.
type StoredMapping struct {
	Domain  string
	Router  netip.Addr
	Created time.Time
}
