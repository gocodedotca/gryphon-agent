//go:build unix

package clientagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// scriptsDir makes a scripts directory holding the given shell scripts, each
// executable by its owner only.
func scriptsDir(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScriptCheckReadsNagiosExitCodes(t *testing.T) {
	dir := scriptsDir(t, map[string]string{
		"ok":       `echo "QUEUE OK - 12 messages | depth=12;500;1000"; echo "second line"; exit 0`,
		"warning":  `echo "QUEUE WARNING - 600 messages"; exit 1`,
		"critical": `echo "QUEUE CRITICAL - 1200 messages"; exit 2`,
		"unknown":  `echo "cannot reach the broker"; exit 3`,
		"silent":   `exit 2`,
		"stderr":   `echo "only on stderr" >&2; exit 1`,
		"odd":      `echo "whatever"; exit 7`,
	})

	for _, tc := range []struct {
		name, msg string
		status    int
	}{
		{"ok", "QUEUE OK - 12 messages", agent.StatusHealthy},
		{"warning", "QUEUE WARNING - 600 messages", agent.StatusWarning},
		{"critical", "QUEUE CRITICAL - 1200 messages", agent.StatusProblem},
		{"unknown", "cannot reach the broker", agent.StatusUnknown},
		{"silent", "silent exited 2 (critical)", agent.StatusProblem},
		{"stderr", "only on stderr", agent.StatusWarning},
		{"odd", "script odd exited 7, which is not a status (0 to 3): whatever", agent.StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postScript(t, dir, tc.name)
			if resp.NewStatusID != tc.status || resp.Status != tc.msg {
				t.Errorf("got %d %q; want %d %q", resp.NewStatusID, resp.Status, tc.status, tc.msg)
			}
		})
	}
}

func TestScriptCheckRefusesWhatItShouldNotRun(t *testing.T) {
	dir := scriptsDir(t, map[string]string{"shared": "exit 0", "plain": "exit 0"})
	if err := os.Chmod(filepath.Join(dir, "shared"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, dir, script, says string
	}{
		{"turned off", "", "shared", "turned off"},
		{"a path", dir, "../shared", "not a script name"},
		{"missing", dir, "absent", "no script called absent"},
		{"writable by everybody", dir, "shared", "writable by every user"},
		{"not executable", dir, "plain", "not executable"},
		{"a directory", dir, "subdir", "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postScript(t, tc.dir, tc.script)
			if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, tc.says) {
				t.Errorf("got %d %q; want unknown saying %q", resp.NewStatusID, resp.Status, tc.says)
			}
		})
	}

	t.Run("a directory writable by everybody runs nothing", func(t *testing.T) {
		open := scriptsDir(t, map[string]string{"fine": "exit 0"})
		if err := os.Chmod(open, 0o777); err != nil {
			t.Fatal(err)
		}
		resp := postScript(t, open, "fine")
		if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "writable by every user") {
			t.Errorf("got %d %q", resp.NewStatusID, resp.Status)
		}
		if ValidateScriptsDir(open) == nil {
			t.Error("ValidateScriptsDir accepted a directory anybody can write to")
		}
	})
}

// The access key is in the agent's environment; it is not in a script's.
func TestScriptCheckDoesNotPassTheAgentsSettings(t *testing.T) {
	t.Setenv("GWC_KEY", "secret-key-value")
	t.Setenv("SCRIPT_TEST_VISIBLE", "yes")
	dir := scriptsDir(t, map[string]string{"env": `echo "key=${GWC_KEY:-none} visible=$SCRIPT_TEST_VISIBLE"`})
	resp := postScript(t, dir, "env")
	if resp.Status != "key=none visible=yes" {
		t.Errorf("script saw %q", resp.Status)
	}
}

func TestScriptCheckStopsASlowScript(t *testing.T) {
	defer func(d time.Duration) { scriptTimeout = d }(scriptTimeout)
	scriptTimeout = 300 * time.Millisecond

	// The sleep is a child of the shell; stopping only the shell would leave
	// it holding the output open until it finished.
	dir := scriptsDir(t, map[string]string{"slow": "sleep 30"})
	started := time.Now()
	resp := postScript(t, dir, "slow")
	if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "did not finish") {
		t.Errorf("got %d %q", resp.NewStatusID, resp.Status)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("took %s to stop", elapsed)
	}
}
