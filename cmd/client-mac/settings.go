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
// The file holds the access key, so it is written readable by its owner only.
type settings struct {
	// Port is the listen address: ":6001" or "6001", or a full host:port.
	Port string `json:"port"`
	// AccessKey is the pre-shared key Gryphon must present. The app generates
	// one the first time it needs one; Copy Access Key puts it on the
	// clipboard for pasting into the host in Gryphon.
	AccessKey string `json:"access_key"`
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

// defaultPort is loopback, unlike clientagent.DefaultAddr: a Mac is reached
// through a tunnel on the same machine, and the app turns itself on at first
// launch, so every interface would put the agent on the local network before
// its owner had chosen anything.
const defaultPort = "127.0.0.1:6001"

func defaultSettings() settings {
	return settings{Port: defaultPort, Enabled: true}
}

func (s settings) agentConfig() (clientagent.Config, error) {
	cfg := clientagent.Config{
		Addr:               s.Port,
		Key:                strings.TrimSpace(s.AccessKey),
		ScriptsDir:         strings.TrimSpace(s.ScriptsDir),
		WatchDirs:          s.WatchDirs,
		AllowPublicTargets: s.AllowPublicTargets,
	}
	if err := clientagent.ValidateKey(cfg.Key); err != nil {
		return clientagent.Config{}, fmt.Errorf("access_key: %w", err)
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
// agent differently from how the user asked -- and would mean a new key.
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
	// and half a settings file is a file with no key, which would mint a
	// new one and quietly stop matching the host in Gryphon.
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// A file from before the key was in it was written world-readable.
	return os.Chmod(f.path, 0o600)
}

// ensureKey loads the settings, generating and saving an access key if they
// have none, and reports whether it did. A key the user typed is kept as it
// is, even a bad one: the agent refuses to start on it and says why, which is
// better than quietly replacing a key they have already pasted into Gryphon.
//
// minted matters to the caller because a new key is not the one Gryphon
// holds: the host there refuses every check until it is pasted in again.
func (f settingsFile) ensureKey() (s settings, minted bool, err error) {
	s, err = f.load()
	if err != nil {
		return s, false, err
	}
	if strings.TrimSpace(s.AccessKey) != "" {
		return s, false, nil
	}
	key, err := clientagent.GenerateKey()
	if err != nil {
		return s, false, err
	}
	s.AccessKey = key
	return s, true, f.save(s)
}

// ensure writes the defaults, with a new access key, if there is no file yet,
// so that Edit Settings… opens something with the keys already in it.
func (f settingsFile) ensure() error {
	if _, err := os.Stat(f.path); err == nil {
		return nil
	}
	_, _, err := f.ensureKey()
	return err
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
