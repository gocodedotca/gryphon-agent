package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey is a well-formed access key.
const testKey = "test-key-0123456789abcdefghijklmnopqrstuvwxyz"

// The agent runs in the same orchestrators the server does, so its own
// variables have to accept a mounted secret too — and the access key is
// exactly the sort of thing an operator would rather not have sitting in
// `docker inspect`.
func TestClientConfigCanComeFromSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		t.Helper()
		path := dir + "/" + name
		// With the trailing newline a mounted secret carries.
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	e := map[string]string{
		"GWC_PORT_FILE":       write("port", ":7002"),
		"GWC_KEY_FILE":        write("key", testKey),
		"GWC_LOG_FORMAT_FILE": write("log_format", "json"),
	}

	cfg, err := loadConfig(nil, func(k string) string { return e[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.agent.Addr != ":7002" {
		t.Errorf("port = %q", cfg.agent.Addr)
	}
	if cfg.logFormat != "json" {
		t.Errorf("logFormat = %q", cfg.logFormat)
	}
	if cfg.agent.Key != testKey {
		t.Errorf("key = %q, want the key from the file without its newline", cfg.agent.Key)
	}
}

// A flag still beats a secret file, the same as it beats a variable.
func TestClientFlagBeatsSecretFile(t *testing.T) {
	path := t.TempDir() + "/port"
	if err := os.WriteFile(path, []byte(":7002"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig([]string{"-port", ":7003"},
		func(k string) string { return map[string]string{"GWC_PORT_FILE": path, "GWC_KEY": testKey}[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.agent.Addr != ":7003" {
		t.Errorf("port = %q, want the flag to win", cfg.agent.Addr)
	}
}

// A named file that is not there means a missing mount, and starting up on the
// default instead would open the agent wider than the operator asked for.
func TestClientMissingSecretFileIsAnError(t *testing.T) {
	_, err := loadConfig(nil, func(k string) string {
		return map[string]string{"GWC_KEY_FILE": "/nonexistent/nowhere"}[k]
	})
	if err == nil {
		t.Error("expected an error when the secret file cannot be read")
	}
}

// There is no starting without a key, and the error says how to get one.
func TestClientRefusesToStartWithoutAKey(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no key":      {},
		"a short key": {"GWC_KEY": "hunter2"},
	} {
		_, err := loadConfig(nil, func(k string) string { return env[k] })
		if err == nil {
			t.Errorf("%s: started", name)
			continue
		}
		if !strings.Contains(err.Error(), "-genkey") {
			t.Errorf("%s: the error does not say how to make a key: %v", name, err)
		}
	}
}

// -genkey needs no key of its own, which is the point of it.
func TestClientGenKeyNeedsNoKey(t *testing.T) {
	cfg, err := loadConfig([]string{"-genkey"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.genKey {
		t.Error("-genkey was not recorded")
	}
}

func TestClientScriptsDir(t *testing.T) {
	env := map[string]string{"GWC_KEY": "test-key-0123456789abcdefghijklmnopqrstuvwxyz"}
	getenv := func(k string) string { return env[k] }

	cfg, err := loadConfig(nil, getenv)
	if err != nil || cfg.agent.ScriptsDir != "" {
		t.Fatalf("default: %q, %v; want script checks off", cfg.agent.ScriptsDir, err)
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	env["GWC_SCRIPTS_DIR"] = dir
	if cfg, err = loadConfig(nil, getenv); err != nil || cfg.agent.ScriptsDir != dir {
		t.Errorf("from the environment: %q, %v", cfg.agent.ScriptsDir, err)
	}

	env["GWC_SCRIPTS_DIR"] = dir + "/missing"
	if _, err := loadConfig(nil, getenv); err == nil {
		t.Error("a scripts directory that does not exist was accepted")
	}
}

func TestClientWatchDirs(t *testing.T) {
	env := map[string]string{"GWC_KEY": "test-key-0123456789abcdefghijklmnopqrstuvwxyz"}
	getenv := func(k string) string { return env[k] }

	cfg, err := loadConfig(nil, getenv)
	if err != nil || len(cfg.agent.WatchDirs) != 0 {
		t.Fatalf("default: %q, %v; want file checks off", cfg.agent.WatchDirs, err)
	}

	a, b := t.TempDir(), t.TempDir()
	env["GWC_WATCH_DIRS"] = a + string(filepath.ListSeparator) + b
	if cfg, err = loadConfig(nil, getenv); err != nil || len(cfg.agent.WatchDirs) != 2 || cfg.agent.WatchDirs[1] != b {
		t.Errorf("from the environment: %q, %v", cfg.agent.WatchDirs, err)
	}
	if cfg, err = loadConfig([]string{"-watch-dirs", a}, getenv); err != nil || len(cfg.agent.WatchDirs) != 1 {
		t.Errorf("the flag wins: %q, %v", cfg.agent.WatchDirs, err)
	}

	env["GWC_WATCH_DIRS"] = filepath.Join(a, "missing")
	if _, err := loadConfig(nil, getenv); err == nil || !strings.Contains(err.Error(), "GWC_WATCH_DIRS") {
		t.Errorf("a watched folder that does not exist: %v; want a refusal naming GWC_WATCH_DIRS", err)
	}
}

// GWC_KEY_FILE=- is the key on standard input, as the systemd unit hands it
// over: only the first line counts, and it wins over GWC_KEY as any _FILE
// twin does.
func TestClientKeyFromStandardInput(t *testing.T) {
	old := keyStdin
	t.Cleanup(func() { keyStdin = old })

	env := map[string]string{"GWC_KEY_FILE": "-", "GWC_KEY": "the-variable-is-not-the-key-0123456789"}
	getenv := func(k string) string { return env[k] }

	keyStdin = strings.NewReader(testKey + "\nanything after the first line\n")
	cfg, err := loadConfig(nil, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.agent.Key != testKey {
		t.Errorf("key = %q, want the first line of standard input", cfg.agent.Key)
	}

	// Nothing on standard input is no key, and the agent will not start
	// without one.
	keyStdin = strings.NewReader("")
	if _, err := loadConfig(nil, getenv); err == nil {
		t.Error("an empty standard input was accepted as a key")
	}
}
