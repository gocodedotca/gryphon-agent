//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey is a well-formed access key.
const testKey = "test-key-0123456789abcdefghijklmnopqrstuvwxyz"

// No file is the defaults.
func TestSettingsMissingFileIsDefaults(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if s != defaultSettings() {
		t.Errorf("got %+v, want defaults", s)
	}
	if !s.Enabled {
		t.Error("a fresh install should start switched on")
	}
}

// A malformed file is an error, not a silent fall-back to the defaults.
func TestSettingsMalformedFileIsAnError(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := os.WriteFile(f.path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.load(); err == nil {
		t.Error("malformed settings loaded without error")
	}
}

// The switch is remembered without disturbing the other settings.
func TestSetEnabledKeepsOtherSettings(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := f.save(settings{Port: ":7001", AccessKey: testKey, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.setEnabled(false); err != nil {
		t.Fatal(err)
	}
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled {
		t.Error("still enabled")
	}
	if s.Port != ":7001" || s.AccessKey != testKey {
		t.Errorf("other settings disturbed: %+v", s)
	}
}

func TestEnsureWritesDefaultsOnce(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := f.ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(`{"port":":9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.path)
	if !strings.Contains(string(b), `":9"`) {
		t.Error("ensure overwrote an existing file")
	}
}

func TestSettingsToAgentConfig(t *testing.T) {
	cfg, err := settings{Port: "6002", AccessKey: " " + testKey + " "}.agentConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "6002" || cfg.Key != testKey {
		t.Errorf("cfg = %+v", cfg)
	}
	for _, key := range []string{"", "hunter2"} {
		if _, err := (settings{AccessKey: key}).agentConfig(); err == nil {
			t.Errorf("access key %q accepted", key)
		}
	}
}

// The first time a key is needed one is made and kept; after that it is the
// same key, because it has been pasted into Gryphon.
func TestEnsureKeyGeneratesOnceAndKeepsIt(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}

	first, minted, err := f.ensureKey()
	if err != nil {
		t.Fatal(err)
	}
	if !minted {
		t.Error("a key was made but ensureKey did not say so")
	}
	if _, err := first.agentConfig(); err != nil {
		t.Fatalf("the generated key is not usable: %v", err)
	}
	again, minted, err := f.ensureKey()
	if err != nil {
		t.Fatal(err)
	}
	if minted {
		t.Error("ensureKey said it made a key when it kept the saved one")
	}
	if again.AccessKey != first.AccessKey {
		t.Error("a second ensureKey replaced the key")
	}

	info, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("settings file mode = %o, want 600: it holds the key", mode)
	}
}

// A key the user typed stays, even an unusable one: replacing it would break
// the host they pasted it into, silently.
func TestEnsureKeyKeepsATypedKey(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := f.save(settings{Port: ":6001", AccessKey: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	s, _, err := f.ensureKey()
	if err != nil {
		t.Fatal(err)
	}
	if s.AccessKey != "hunter2" {
		t.Errorf("a typed key was replaced with %q", s.AccessKey)
	}
}

// A file written before the key existed was world-readable; saving tightens it.
func TestSaveTightensAnExistingFile(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := os.WriteFile(f.path, []byte(`{"port":":6001"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.ensureKey(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(f.path)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
}

func TestLoginItemPlist(t *testing.T) {
	b, err := renderLoginItem("com.example.agent", "/Applications/Gryphon Agent.app/Contents/MacOS/client-mac")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"<string>com.example.agent</string>",
		"<string>/Applications/Gryphon Agent.app/Contents/MacOS/client-mac</string>",
		"<key>RunAtLoad</key>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %s:\n%s", want, s)
		}
	}
}

// A save goes through a file beside the real one and is renamed over it, so
// nothing is left behind and the real file is always whole.
func TestSaveLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	f := settingsFile{path: filepath.Join(dir, "config.json")}
	if err := f.save(settings{Port: ":6001", AccessKey: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
	s, err := f.load()
	if err != nil || s.AccessKey != "hunter2" {
		t.Errorf("load after save = %+v, %v", s, err)
	}
}
