package storage

import (
	"slices"
	"time"

	"github.com/mycoria/mycoria/m"
)

// StoredRouter is the format used to store router information.
type StoredRouter struct {
	Address    *m.PublicAddress `json:"address,omitempty"    yaml:"address,omitempty"`
	PublicInfo *m.RouterInfo    `json:"publicInfo,omitempty" yaml:"publicInfo,omitempty"`

	// Universe is the universe the router was observed in.
	Universe string `json:"universe,omitempty" yaml:"universe,omitempty"`

	// Offline signifies that the router has announced it is going offline.
	Offline bool `json:"offline,omitempty" yaml:"offline,omitempty"`

	CreatedAt time.Time  `json:"createdAt,omitempty" yaml:"createdAt,omitempty"`
	UpdatedAt time.Time  `json:"updatedAt,omitempty" yaml:"updatedAt,omitempty"`
	UsedAt    *time.Time `json:"usedAt,omitempty"    yaml:"usedAt,omitempty"`
}

// RouterQuery is a query on the storage.
type RouterQuery struct {
	results []*StoredRouter

	where func(a *StoredRouter) bool
	sort  func(a, b *StoredRouter) int
	max   int
}

// NewRouterQuery returns a new router query.
func NewRouterQuery(
	where func(a *StoredRouter) bool,
	sort func(a, b *StoredRouter) int,
	max int,
) *RouterQuery {
	return &RouterQuery{
		results: make([]*StoredRouter, 0, max),
		where:   where,
		sort:    sort,
		max:     max,
	}
}

// Add attempts to add the given query to the query result.
func (sq *RouterQuery) Add(entry *StoredRouter) {
	switch {
	case sq.where != nil && !sq.where(entry):
		// Ignore entry if it does not match the query filter.

	case len(sq.results) < sq.max:
		// If we haven't reached max yet, add to results.
		sq.results = append(sq.results, entry)
		// If we have reached max, do an initial sort.
		if len(sq.results) >= sq.max && sq.sort != nil {
			slices.SortFunc[[]*StoredRouter, *StoredRouter](sq.results, sq.sort)
		}

	case sq.sort == nil:
	// Stop here if we don't have a sort func.

	case sq.sort(entry, sq.results[len(sq.results)-1]) > 0:
	// Don't add value if it sorts behind the last entry.

	default:
		// Otherwise, replace last value and sort again.
		sq.results[len(sq.results)-1] = entry
		slices.SortFunc[[]*StoredRouter, *StoredRouter](sq.results, sq.sort)
	}
}

// Result returns the query result.
func (sq *RouterQuery) Result() []*StoredRouter {
	// Sort if not reached max.
	if len(sq.results) < sq.max && sq.sort != nil {
		slices.SortFunc[[]*StoredRouter, *StoredRouter](sq.results, sq.sort)
	}

	return sq.results
}
