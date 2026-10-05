//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocodedotca/gryphon-agent/pkg/clientagent"
)

// settings is the file at ~/Library/Application Support/Gryphon Agent/
// config.json. It is what the Linux agent takes from its flags and
// environment, minus the log format, plus the position of the switch.
//
// The file holds the token, so it is written readable by its owner only.
type settings struct {
	// Token is what the agent connects to Gryphon with, issued on the
	// host's page there and given to the app with Enter Token….
	Token string `json:"token"`
	// Server is the Gryphon to connect to, when it is not the default. There
	// is no menu item for it: a customer never changes it, and a developer
	// or a self-hosted installation edits this file.
	Server string `json:"server,omitempty"`
	// AllowInsecureServer lets Server be http://, for a server on this Mac
	// or an installation reached only across its own network.
	AllowInsecureServer bool `json:"allow_insecure_server,omitempty"`
	// Enabled is where the switch was left; the app comes back the same way.
	Enabled bool `json:"enabled"`
	// ScriptsDir is the directory script checks run executables from, as
	// GWC_SCRIPTS_DIR is for the Linux agent. There is no menu item for it:
	// choosing what may run on this Mac is done by editing this file, on
	// purpose. Empty, the default, turns script checks off.
	ScriptsDir string `json:"scripts_dir,omitempty"`
	// WatchDirs are the folders file-age checks may look in, as
	// GWC_WATCH_DIRS is for the Linux agent, and edited here for the same
	// reason as ScriptsDir. Empty, the default, turns file checks off.
	WatchDirs []string `json:"watch_dirs,omitempty"`
	// AllowPublicTargets lets the network and database checks dial the public
	// internet, as GWC_ALLOW_PUBLIC_TARGETS does for the Linux agent. Off by
	// default, so the agent reaches this Mac's own network and no further.
	// Edited in this file rather than offered as a menu item, like ScriptsDir
	// and for the same reason.
	AllowPublicTargets bool `json:"allow_public_targets,omitempty"`
}

func defaultSettings() settings {
	return settings{Enabled: true}
}

// errNoToken is a settings file with no token in it yet.
var errNoToken = errors.New("no token yet: choose Enter Token… and paste the token from this host's page in Gryphon")

func (s settings) agentConfig() (clientagent.Config, error) {
	cfg := clientagent.Config{
		Key:                 strings.TrimSpace(s.Token),
		Server:              strings.TrimSpace(s.Server),
		AllowInsecureServer: s.AllowInsecureServer,
		ScriptsDir:          strings.TrimSpace(s.ScriptsDir),
		WatchDirs:           s.WatchDirs,
		AllowPublicTargets:  s.AllowPublicTargets,
	}
	if cfg.Key == "" {
		return clientagent.Config{}, errNoToken
	}
	if err := clientagent.ValidateKey(cfg.Key); err != nil {
		return clientagent.Config{}, fmt.Errorf("token: %w", err)
	}
	if _, err := clientagent.ConnectURL(cfg.Server, cfg.AllowInsecureServer); err != nil {
		return clientagent.Config{}, err
	}
	if cfg.ScriptsDir != "" {
		if err := clientagent.ValidateScriptsDir(cfg.ScriptsDir); err != nil {
			return clientagent.Config{}, fmt.Errorf("scripts_dir: %w", err)
		}
	}
	if err := clientagent.ValidateWatchDirs(cfg.WatchDirs); err != nil {
		return clientagent.Config{}, fmt.Errorf("watch_dirs: %w", err)
	}
	return cfg, nil
}

// settingsFile knows where the settings live and how to read and write them.
type settingsFile struct {
	path string
}

func defaultSettingsFile() settingsFile {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return settingsFile{path: filepath.Join(home, "Library", "Application Support", appName, "config.json")}
}

// load reads the file. A missing file is the defaults, not an error. A
// malformed one is an error, because starting on the defaults would run the
// agent differently from how the user asked -- and without its token.
func (f settingsFile) load() (settings, error) {
	s := defaultSettings()
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("settings file %s: %w", f.path, err)
	}
	return s, nil
}

func (f settingsFile) save(s settings) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Written beside the file and renamed over it, so a crash or a full disk
	// mid-write leaves the old settings rather than half of the new ones --
	// and half a settings file is a file with no token.
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// A file from before a secret was in it was written world-readable.
	return os.Chmod(f.path, 0o600)
}

// ensure writes the defaults if there is no file yet, so that Edit
// Settings… opens something with the keys already in it.
func (f settingsFile) ensure() error {
	if _, err := os.Stat(f.path); err == nil {
		return nil
	}
	return f.save(defaultSettings())
}

// setToken records a token, keeping the other settings, and switches the
// agent on: a token is given in order to connect.
func (f settingsFile) setToken(token string) error {
	s, err := f.load()
	if err != nil {
		return err
	}
	s.Token = strings.TrimSpace(token)
	s.Enabled = true
	return f.save(s)
}

// setEnabled records the switch without touching the other settings, and
// without failing when the file is malformed -- the user is presumably about
// to fix it.
func (f settingsFile) setEnabled(enabled bool) error {
	s, err := f.load()
	if err != nil {
		return err
	}
	s.Enabled = enabled
	return f.save(s)
}
