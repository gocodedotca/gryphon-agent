package clientagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// winScriptsDir makes a scripts folder that only SYSTEM, Administrators and
// the test's own account can change, plus any extra SDDL entries, holding the
// given files.
func winScriptsDir(t *testing.T, extraACEs string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	self := agentSID()
	if self == nil {
		t.Fatal("cannot read the test's own account")
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + self.String() + ")" + extraACEs
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.ReplaceAll(body, "\n", "\r\n")), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestWindowsScriptCheckReadsExitCodes(t *testing.T) {
	dir := winScriptsDir(t, "", map[string]string{
		"ok.bat":    "@echo QUEUE OK - 12 messages ^| depth=12\n@exit /b 0",
		"crit.cmd":  "@echo QUEUE CRITICAL\n@exit /b 2",
		"warn.ps1":  "Write-Output 'careful'\nexit 1",
		"notes.txt": "not a program",
	})
	for _, tc := range []struct {
		name, msg string
		status    int
	}{
		{"ok.bat", "QUEUE OK - 12 messages", agent.StatusHealthy},
		{"crit.cmd", "QUEUE CRITICAL", agent.StatusProblem},
		{"warn.ps1", "careful", agent.StatusWarning},
		{"notes.txt", "script notes.txt is not executable (" + notExecutableHint + ")", agent.StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postScript(t, dir, tc.name)
			if resp.NewStatusID != tc.status || resp.Status != tc.msg {
				t.Errorf("got %d %q; want %d %q", resp.NewStatusID, resp.Status, tc.status, tc.msg)
			}
		})
	}
}

func TestWindowsScriptCheckRefusesAFolderOthersCanChange(t *testing.T) {
	// WD is Everyone; write data on a folder is the right to add a file.
	dir := winScriptsDir(t, "(A;OICI;0x2;;;WD)", map[string]string{"ok.bat": "@exit /b 0"})
	err := ValidateScriptsDir(dir)
	if err == nil || !strings.Contains(err.Error(), "can be changed by") {
		t.Fatalf("got %v, want a refusal naming who can change it", err)
	}
	resp := postScript(t, dir, "ok.bat")
	if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "no script runs from it") {
		t.Errorf("got %d %q", resp.NewStatusID, resp.Status)
	}
}

func TestWindowsScriptCheckAcceptsReadOnlyEntriesForOthers(t *testing.T) {
	// BU is Users: reading and running is fine, only change is not.
	dir := winScriptsDir(t, "(A;OICI;0x1200a9;;;BU)", nil)
	if err := ValidateScriptsDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsScriptCheckDoesNotPassTheAgentsSettings(t *testing.T) {
	t.Setenv("GWC_KEY", "secret-key-value")
	t.Setenv("SCRIPT_TEST_VISIBLE", "yes")
	dir := winScriptsDir(t, "", map[string]string{
		"env.ps1": `Write-Output "key=$($env:GWC_KEY) visible=$($env:SCRIPT_TEST_VISIBLE)"`,
	})
	resp := postScript(t, dir, "env.ps1")
	if resp.Status != "key= visible=yes" {
		t.Errorf("script saw %q", resp.Status)
	}
}

func TestWindowsScriptCheckStopsASlowScriptAndWhatItStarted(t *testing.T) {
	defer func(d time.Duration) { scriptTimeout = d }(scriptTimeout)
	scriptTimeout = 500 * time.Millisecond

	// ping is a child of cmd.exe; ending only cmd.exe would leave it
	// holding the output open until it finished.
	dir := winScriptsDir(t, "", map[string]string{"slow.bat": "@ping -n 30 127.0.0.1"})
	started := time.Now()
	resp := postScript(t, dir, "slow.bat")
	if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "did not finish") {
		t.Errorf("got %d %q", resp.NewStatusID, resp.Status)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("took %s to stop", elapsed)
	}
}
