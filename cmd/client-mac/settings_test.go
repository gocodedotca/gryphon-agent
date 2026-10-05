//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// testKey is a well-formed token.
const testKey = "test-key-0123456789abcdefghijklmnopqrstuvwxyz"

// No file is the defaults.
func TestSettingsMissingFileIsDefaults(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, defaultSettings()) {
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
	if err := f.save(settings{Server: "https://gryphon.example.test", Token: testKey, Enabled: true}); err != nil {
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
	if s.Server != "https://gryphon.example.test" || s.Token != testKey {
		t.Errorf("other settings disturbed: %+v", s)
	}
}

func TestEnsureWritesDefaultsOnce(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := f.ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(`{"server":"https://nine.example.test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.path)
	if !strings.Contains(string(b), `nine.example.test`) {
		t.Error("ensure overwrote an existing file")
	}
}

func TestSettingsToAgentConfig(t *testing.T) {
	cfg, err := settings{Token: " " + testKey + " "}.agentConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Key != testKey || cfg.Server != "" {
		t.Errorf("cfg = %+v", cfg)
	}
	if _, err := (settings{}).agentConfig(); !errors.Is(err, errNoToken) {
		t.Errorf("no token: %v; want errNoToken, which says to enter one", err)
	}
	if _, err := (settings{Token: "hunter2"}).agentConfig(); err == nil {
		t.Error("a malformed token was accepted")
	}
	if _, err := (settings{Token: testKey, Server: "http://localhost:4000"}).agentConfig(); err == nil {
		t.Error("an http:// server was accepted without being allowed")
	}
	if _, err := (settings{Token: testKey, Server: "http://localhost:4000", AllowInsecureServer: true}).agentConfig(); err != nil {
		t.Errorf("an allowed http:// server: %v", err)
	}
}

// A token entered is saved, readable by its owner only, and switches the
// agent on; nothing else in the file changes.
func TestSetToken(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := f.save(settings{Server: "https://gryphon.example.test", ScriptsDir: "/opt/scripts"}); err != nil {
		t.Fatal(err)
	}
	if err := f.setToken(" " + testKey + "\n"); err != nil {
		t.Fatal(err)
	}
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Token != testKey || !s.Enabled || s.Server != "https://gryphon.example.test" || s.ScriptsDir != "/opt/scripts" {
		t.Errorf("after setToken: %+v", s)
	}
	info, _ := os.Stat(f.path)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600: it holds the token", mode)
	}
}

// A file written before a secret was in it was world-readable; saving
// tightens it.
func TestSaveTightensAnExistingFile(t *testing.T) {
	f := settingsFile{path: filepath.Join(t.TempDir(), "config.json")}
	if err := os.WriteFile(f.path, []byte(`{"enabled":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.setToken(testKey); err != nil {
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
	if err := f.save(settings{Token: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
	s, err := f.load()
	if err != nil || s.Token != "hunter2" {
		t.Errorf("load after save = %+v, %v", s, err)
	}
}
