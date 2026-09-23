package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Credentials is ~/.agentguards/credentials.json — the key every AgentGuards hook
// falls back to when no env var or plugin setting provides one. The hooks read
// only "api_key"; keep this shape in sync with their _installer_key helpers.
type Credentials struct {
	APIKey string `json:"api_key"`
}

func configDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentguards"), nil
}

func credentialsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func validKey(k string) bool {
	return strings.HasPrefix(k, "ag_") && len(k) > len("ag_")+8
}

func loadCredentials() (Credentials, error) {
	var c Credentials
	p, err := credentialsPath()
	if err != nil {
		return c, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	c.APIKey = strings.TrimSpace(c.APIKey)
	if !validKey(c.APIKey) {
		return c, errors.New("saved key is not an AgentGuards key")
	}
	return c, nil
}

// saveCredentials writes the key readable by the current user only. The file is
// replaced atomically so a hook never reads a half-written key.
func saveCredentials(c Credentials) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	p, _ := credentialsPath()
	return os.Rename(tmp.Name(), p)
}

func removeCredentials() error {
	p, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
