package state

import "slices"

// StorageQuery is a query on the storage.
type StorageQuery struct {
	results []*StoredInfo

	where func(a *StoredInfo) bool
	sort  func(a, b *StoredInfo) int
	max   int
}

// NewQuery returns a new query.
func NewQuery(
	where func(a *StoredInfo) bool,
	sort func(a, b *StoredInfo) int,
	max int,
) *StorageQuery {
	return &StorageQuery{
		results: make([]*StoredInfo, 0, max),
		where:   where,
		sort:    sort,
		max:     max,
	}
}

// Add attempts to add the given query to the query result.
func (sq *StorageQuery) Add(entry *StoredInfo) {
	switch {
	case sq.where != nil && !sq.where(entry):
		// Ignore entry if it does not match the query filter.

	case len(sq.results) < sq.max:
		// If we haven't reached max yet, add to results.
		sq.results = append(sq.results, entry)
		// If we have reached max, do an initial sort.
		if len(sq.results) >= sq.max && sq.sort != nil {
			slices.SortFunc[[]*StoredInfo, *StoredInfo](sq.results, sq.sort)
		}

	case sq.sort == nil:
	// Stop here if we don't have a sort func.

	case sq.sort(entry, sq.results[len(sq.results)-1]) > 0:
	// Don't add value if it sorts behind the last entry.

	default:
		// Otherwise, replace last value and sort again.
		sq.results[len(sq.results)-1] = entry
		slices.SortFunc[[]*StoredInfo, *StoredInfo](sq.results, sq.sort)
	}
}

// Result returns the query result.
func (sq *StorageQuery) Result() []*StoredInfo {
	// Sort if not reached max.
	if len(sq.results) < sq.max && sq.sort != nil {
		slices.SortFunc[[]*StoredInfo, *StoredInfo](sq.results, sq.sort)
	}

	return sq.results
}
