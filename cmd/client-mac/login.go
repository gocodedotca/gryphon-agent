//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// Open at Login is a LaunchAgent: a plist in ~/Library/LaunchAgents that
// launchd reads when the user logs in. It is the oldest of the mechanisms and
// the only one a user can find and delete by hand, which for a monitoring
// agent is a feature.

func loginItemPath(bundleID string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, "Library", "LaunchAgents", bundleID+".plist")
}

func loginItemInstalled(bundleID string) bool {
	_, err := os.Stat(loginItemPath(bundleID))
	return err == nil
}

var loginItemTemplate = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Program}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`))

// renderLoginItem is the plist for launching program at login.
func renderLoginItem(bundleID, program string) ([]byte, error) {
	var b bytes.Buffer
	err := loginItemTemplate.Execute(&b, struct{ Label, Program string }{bundleID, program})
	return b.Bytes(), err
}

// installLoginItem writes the plist pointing at this executable and loads it,
// so that the item is live now and not only after the next login.
func installLoginItem(bundleID string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	plist, err := renderLoginItem(bundleID, exe)
	if err != nil {
		return err
	}
	path := loginItemPath(bundleID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, plist, 0o644); err != nil {
		return err
	}
	// Loading a plist for an app that is already running is harmless: launchd
	// records the job and does nothing until the next login.
	if out, err := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), path).CombinedOutput(); err != nil {
		// Already loaded is the one failure that is not one.
		if !alreadyLoaded(out) {
			return fmt.Errorf("launchctl bootstrap: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func removeLoginItem(bundleID string) error {
	path := loginItemPath(bundleID)
	// Unload first, or launchd keeps the job until logout. Failure here is
	// fine: the file going away is what matters for the next login.
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), bundleID)).Run()
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// alreadyLoaded recognises launchctl's complaint about a job it already has.
// The wording and code vary by release: "Input/output error" (5) on older
// systems, "Operation already in progress" (37) on newer ones.
func alreadyLoaded(out []byte) bool {
	s := string(out)
	for _, m := range []string{"already", "Input/output error", ": 37:", ": 5:"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
