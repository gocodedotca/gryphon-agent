package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceReadsAgentEnvAndDefaults(t *testing.T) {
	pd := t.TempDir()
	t.Setenv("ProgramData", pd)
	t.Setenv("GWC_KEY", "")
	dir := filepath.Join(pd, "Gryphon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const key = "test-key-0123456789abcdefghijklmnopqrstuvwxyz"
	if err := os.WriteFile(filepath.Join(dir, "agent_key"), []byte(key+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.env"), []byte("GWC_MAX_CONCURRENT=5\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	getenv, err := serviceGetenv()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(nil, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.agent.Key != key {
		t.Errorf("key %q, want the one in agent_key", cfg.agent.Key)
	}
	if cfg.agent.MaxConcurrent != 5 {
		t.Errorf("max concurrent %d, want agent.env's 5", cfg.agent.MaxConcurrent)
	}
}

func TestServiceKeyFromTheEnvironmentWinsOverTheDefaultFile(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	t.Setenv("GWC_KEY", "from-the-environment")
	getenv, err := serviceGetenv()
	if err != nil {
		t.Fatal(err)
	}
	if got := getenv("GWC_KEY_FILE"); got != "" {
		t.Errorf("GWC_KEY_FILE defaulted to %q beside a set GWC_KEY, which would hide it", got)
	}
}
