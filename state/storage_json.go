package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"
)

// JSONFileStorage is a simple storage implementation using a single json file
// that is read on start and writton when stopped.
type JSONFileStorage struct {
	MemStorage

	filename string
}

// JSONStorageFormat is the format in which the JSONFileStorage stores the state.
type JSONStorageFormat struct {
	Routers map[netip.Addr]*StoredInfo `json:"routers,omitempty" yaml:"routers,omitempty"`
}

// NewJSONFileStorage loads the json file at the given location and returns a new storage.
func NewJSONFileStorage(filename string) (*JSONFileStorage, error) {
	s := &JSONFileStorage{
		filename: filename,
	}

	data, err := os.ReadFile(filename)
	switch {
	case err == nil:
		var stored JSONStorageFormat
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, fmt.Errorf("unmarshal json: %w", err)
		}
		s.entries = stored.Routers

	case errors.Is(err, os.ErrNotExist):
		// File does not exist, start empty.

	default:
		return nil, fmt.Errorf("read file %q: %w", s.filename, err)
	}

	// Ensure s.entries always has a map.
	if s.entries == nil {
		s.entries = make(map[netip.Addr]*StoredInfo)
	}

	return s, nil
}

// Stop writes to storage to file.
func (s *JSONFileStorage) Stop() error {
	data, err := json.Marshal(&JSONStorageFormat{
		Routers: s.entries,
	})
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	err = os.WriteFile(s.filename, data, 0o0644) //nolint:gosec // no secrets
	if err != nil {
		return fmt.Errorf("write file %q: %w", s.filename, err)
	}

	return nil
}

// Load returns an entry from the storage.
func (s *JSONFileStorage) Load(ip netip.Addr) *StoredInfo {
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
