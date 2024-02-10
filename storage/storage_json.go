package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/mycoria/mycoria/mgr"
)

// JSONFileStorage is a simple storage implementation using a single json file
// that is read on start and writton when stopped.
type JSONFileStorage struct {
	MemStorage

	filename string
}

// JSONStorageFormat is the format in which the JSONFileStorage stores the state.
type JSONStorageFormat struct {
	Routers  map[netip.Addr]*StoredRouter `json:"routers,omitempty"  yaml:"routers,omitempty"`
	Mappings map[string]StoredMapping     `json:"mappings,omitempty" yaml:"mappings,omitempty"`
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
		s.routers = stored.Routers
		s.mappings = stored.Mappings

	case errors.Is(err, os.ErrNotExist):
		// File does not exist, start empty.

	default:
		return nil, fmt.Errorf("read file %q: %w", s.filename, err)
	}

	// Ensure maps are initialized.
	if s.routers == nil {
		s.routers = make(map[netip.Addr]*StoredRouter)
	}
	if s.mappings == nil {
		s.mappings = make(map[string]StoredMapping)
	}

	return s, nil
}

// Stop writes to storage to file.
func (s *JSONFileStorage) Stop(mgr *mgr.Manager) error {
	data, err := json.Marshal(&JSONStorageFormat{
		Routers:  s.routers,
		Mappings: s.mappings,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal json storage: %w", err)
	}
	err = os.WriteFile(s.filename, data, 0o0644) //nolint:gosec // no secrets
	if err != nil {
		return fmt.Errorf("failed to write json storage to %s: %w", s.filename, err)
	}
	return nil
}
