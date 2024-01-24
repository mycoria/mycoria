package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads the config from the given file.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file at %s: %w", filename, err)
	}

	store := &Store{}
	switch {
	case strings.HasSuffix(filename, ".json"):
		err = json.Unmarshal(data, store)
	case strings.HasSuffix(filename, ".yml"):
		fallthrough
	case strings.HasSuffix(filename, ".yaml"):
		err = yaml.Unmarshal(data, store)
	default:
		return nil, errors.New("unknown config file type")
	}
	if err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", filename, err)
	}

	return store.Parse()
}

// SaveTo write the config to the given file.
func (c *Config) SaveTo(filename string) error {
	var (
		data []byte
		err  error
	)
	switch {
	case strings.HasSuffix(filename, ".json"):
		data, err = json.MarshalIndent(c, "", "  ")
	case strings.HasSuffix(filename, ".yml"):
		fallthrough
	case strings.HasSuffix(filename, ".yaml"):
		data, err = yaml.Marshal(c)
	default:
		return errors.New("unknown config file type")
	}
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.WriteFile(filename, data, 0o0600); err != nil {
		return fmt.Errorf("write config to %s: %w", filename, err)
	}
	return nil
}
