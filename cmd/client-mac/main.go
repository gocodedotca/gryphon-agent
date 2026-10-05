//go:build darwin

// Command client-mac is the Gryphon client agent as a macOS menu bar app.
//
// The agent itself is pkg/clientagent; this wraps it in the interface a Mac
// user expects -- an icon in the menu bar with an on/off switch and a line
// saying whether it is connected -- and in the configuration a Mac app can
// have, which is a file rather than flags. It connects out to Gryphon, so
// the Mac needs no open port and no tunnel.
// It has no window and no Dock icon (LSUIElement in the bundle's Info.plist).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "embed"

	"fyne.io/systray"
	"github.com/gocodedotca/gryphon-agent/pkg/clientagent"
	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

// appName is what the user sees: the folder under Application Support, the
// log file, the menu. The bundle name in Info.plist must match.
const appName = "Gryphon Agent"

// bundleID names the LaunchAgent plist. The build overrides it with the
// bundle's real identifier (-ldflags "-X main.bundleID=...") so the two agree.
var bundleID = "com.gryphon.agent"

//go:embed icon.png
var iconPNG []byte

type app struct {
	log      *slog.Logger
	settings settingsFile
	agent    *clientagent.Connector

	status     *systray.MenuItem
	toggle     *systray.MenuItem
	atLogin    *systray.MenuItem
	enterToken *systray.MenuItem
	update     *systray.MenuItem
	// updateURL is the release page of the newer build, once one is known.
	updateURL string
}

func main() {
	log := openLog()
	log.Info("starting "+appName, "version", version.Version())

	a := &app{log: log, settings: defaultSettingsFile()}
	systray.Run(a.ready, a.exit)
}

// openLog logs to ~/Library/Logs, where Console.app looks; an app launched
// from Finder has no stdout anyone can see.
func openLog() *slog.Logger {
	home, err := os.UserHomeDir()
	if err != nil {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	path := filepath.Join(home, "Library", "Logs", appName+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(f, nil))
}

// ready builds the menu. systray calls it once its own loop is running.
func (a *app) ready() {
	systray.SetTemplateIcon(iconPNG, iconPNG)
	systray.SetTooltip(appName)

	a.status = systray.AddMenuItem(appName, "")
	a.status.Disable()
	systray.AddSeparator()
	a.toggle = systray.AddMenuItem("Turn On", "Connect to Gryphon, or disconnect")
	a.enterToken = systray.AddMenuItem("Enter Token…", "Paste the token from this host's page in Gryphon")
	a.atLogin = systray.AddMenuItemCheckbox("Open at Login", "", loginItemInstalled(bundleID))
	edit := systray.AddMenuItem("Edit Settings…", "Open the settings file in your editor")
	systray.AddSeparator()
	about := systray.AddMenuItem("Version "+version.Version(), "")
	about.Disable()
	// Shown only once a newer release is known; see updates.go.
	a.update = systray.AddMenuItem("Update available", "Open the release page")
	a.update.Hide()
	quit := systray.AddMenuItem("Quit "+appName, "")
	go a.watchForUpdates()

	// Honour the switch as it was left last time.
	s, err := a.settings.load()
	if err != nil {
		a.showError(err)
	} else if s.Enabled {
		a.turnOn()
	} else {
		a.showOff()
	}

	go func() {
		for {
			select {
			case <-a.toggle.ClickedCh:
				if a.agent != nil && a.agent.Running() {
					a.turnOff()
				} else {
					a.turnOn()
				}
			case <-a.atLogin.ClickedCh:
				a.toggleLoginItem()
			case <-a.enterToken.ClickedCh:
				a.askForToken()
			case <-edit.ClickedCh:
				a.editSettings()
			case <-a.update.ClickedCh:
				a.openUpdate()
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// exit runs when the systray loop ends, whatever ended it.
func (a *app) exit() {
	a.stopAgent()
	a.log.Info("stopped")
}

// turnOn re-reads the settings and starts the agent. Reading them here is
// what makes Edit Settings… take effect without a preferences window: change
// the file, turn the agent off and on. From then on the status line follows
// the connection.
func (a *app) turnOn() {
	s, err := a.settings.load()
	if err != nil {
		a.showError(err)
		return
	}
	cfg, err := s.agentConfig()
	if err != nil {
		a.showError(err)
		return
	}

	a.stopAgent()
	a.agent = clientagent.NewConnector(cfg, a.log, a.showStatus)
	if err := a.agent.Start(); err != nil {
		a.agent = nil
		a.showError(err)
		return
	}
	a.toggle.SetTitle("Turn Off")
	a.remember(true)
}

// showStatus is the connection's state in the status line, where the user
// looks. The server is named when it is not the default, so a build pointed
// at a development server cannot quietly report there.
func (a *app) showStatus(st clientagent.ConnStatus) {
	where := ""
	if st.Server != clientagent.DefaultServer {
		where = " to " + st.Server
	}
	var line string
	switch st.State {
	case clientagent.Connecting:
		line = "connecting" + where + "…"
	case clientagent.Connected:
		line = "connected" + where
	case clientagent.Retrying:
		line = "not connected" + where + "; trying again"
		if st.Err != nil {
			line = "not connected" + where + " (" + st.Err.Error() + "); trying again"
		}
	case clientagent.Refused:
		line = "the token was refused: choose Enter Token… to give it a new one"
		if errors.Is(st.Err, clientagent.ErrIncompatible) {
			line = "this Gryphon needs a newer agent: update the app"
		}
	case clientagent.Stopped:
		line = "off"
	}
	a.status.SetTitle(appName + " — " + line)
}

func (a *app) turnOff() {
	a.stopAgent()
	a.showOff()
	a.remember(false)
}

func (a *app) showOff() {
	a.status.SetTitle(appName + " — off")
	a.toggle.SetTitle("Turn On")
}

// showError puts the reason in the status line, where the user will look
// when the switch did not take. A dialog would be the only window the app
// has, and one it does not need.
func (a *app) showError(err error) {
	a.log.Error("cannot turn on", "error", err)
	a.status.SetTitle(appName + " — " + err.Error())
	a.toggle.SetTitle("Turn On")
}

func (a *app) stopAgent() {
	if a.agent == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.agent.Stop(ctx); err != nil {
		a.log.Error("stop", "error", err)
	}
	a.agent = nil
}

// remember records the switch so a relaunch comes back the same way.
func (a *app) remember(enabled bool) {
	if err := a.settings.setEnabled(enabled); err != nil {
		a.log.Error("cannot save settings", "error", err)
	}
}

func (a *app) toggleLoginItem() {
	var err error
	if a.atLogin.Checked() {
		err = removeLoginItem(bundleID)
	} else {
		err = installLoginItem(bundleID)
	}
	if err != nil {
		a.log.Error("open at login", "error", err)
	}
	if loginItemInstalled(bundleID) {
		a.atLogin.Check()
	} else {
		a.atLogin.Uncheck()
	}
}

// tokenPrompt asks for the token in a dialog that does not show what is
// pasted into it. The app has no window of its own; AppleScript's dialog is
// the Mac's standard one, and Cancel ends the script with an error, which is
// how a cancel is told from an empty answer.
const tokenPrompt = `text returned of (display dialog "Paste the token from this host's page in Gryphon." ` +
	`default answer "" with hidden answer with title "Gryphon Agent" ` +
	`buttons {"Cancel", "Connect"} default button "Connect")`

// askForToken takes a token, saves it and connects with it. A token that is
// not one is said so in the status line; one Gryphon refuses is said so as
// soon as the agent tries it.
func (a *app) askForToken() {
	out, err := exec.Command("osascript", "-e", tokenPrompt).Output()
	if err != nil {
		return // cancelled
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return
	}
	if err := clientagent.ValidateKey(token); err != nil {
		a.showError(fmt.Errorf("that is not a token (%w): copy it whole from the host's page", err))
		return
	}
	if err := a.settings.setToken(token); err != nil {
		a.showError(err)
		return
	}
	a.log.Info("a new token was entered")
	a.turnOn()
}

// editSettings makes sure the file exists, then hands it to the default
// text editor.
func (a *app) editSettings() {
	if err := a.settings.ensure(); err != nil {
		a.log.Error("cannot create settings file", "error", err)
		return
	}
	if err := exec.Command("open", "-t", a.settings.path).Run(); err != nil {
		a.log.Error("cannot open settings file", "error", err)
	}
}
