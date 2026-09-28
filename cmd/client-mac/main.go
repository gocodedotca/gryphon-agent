//go:build darwin

// Command client-mac is the Gryphon client agent as a macOS menu bar app.
//
// The agent itself is pkg/clientagent; this wraps it in the interface a Mac
// user expects -- an icon in the menu bar with an on/off switch -- and in
// the configuration a Mac app can have, which is a file rather than flags.
// It has no window and no Dock icon (LSUIElement in the bundle's Info.plist).
package main

import (
	"context"
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
	agent    *clientagent.Agent

	status  *systray.MenuItem
	toggle  *systray.MenuItem
	atLogin *systray.MenuItem
	copyKey *systray.MenuItem
	update  *systray.MenuItem
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
	a.toggle = systray.AddMenuItem("Turn On", "Start or stop answering the Gryphon server")
	a.atLogin = systray.AddMenuItemCheckbox("Open at Login", "", loginItemInstalled(bundleID))
	a.copyKey = systray.AddMenuItem(copyKeyTitle, "Copy the key to paste into this host in Gryphon")
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
			case <-a.copyKey.ClickedCh:
				a.copyAccessKey()
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
// the file, turn the agent off and on.
func (a *app) turnOn() {
	s, minted, err := a.settings.ensureKey()
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
	a.agent = clientagent.New(cfg, a.log)
	if err := a.agent.Start(); err != nil {
		a.agent = nil
		a.showError(fmt.Errorf("cannot listen on %s: %w", cfg.Addr, err))
		return
	}

	title := appName + " — listening on " + a.agent.Addr().String()
	if minted {
		// A key made now is not the one Gryphon holds. Said where the user
		// looks, and in the log, rather than discovered as a host that
		// refuses every check.
		a.log.Warn("a new access key was made; the host in Gryphon needs it")
		title += " — new access key made: Copy Access Key and paste it into Gryphon"
	}
	a.status.SetTitle(title)
	a.toggle.SetTitle("Turn Off")
	a.remember(true)
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

const copyKeyTitle = "Copy Access Key"

// copyAccessKey puts the key on the clipboard, making one first if there is
// none yet, and says so in the item's own title for a moment -- a menu that
// closes on click gives no other place to confirm it.
func (a *app) copyAccessKey() {
	s, _, err := a.settings.ensureKey()
	if err != nil {
		a.showError(err)
		return
	}
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(strings.TrimSpace(s.AccessKey))
	if err := cmd.Run(); err != nil {
		a.log.Error("cannot copy the access key", "error", err)
		return
	}
	a.copyKey.SetTitle("Access Key Copied")
	time.AfterFunc(3*time.Second, func() { a.copyKey.SetTitle(copyKeyTitle) })
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
