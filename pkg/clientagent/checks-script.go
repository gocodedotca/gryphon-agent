package clientagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// The script check: an executable the agent's administrator put in the scripts
// directory, run by file name, judged by its exit code.
//
// The exit codes are the Nagios plugin convention -- 0 OK, 1 warning, 2
// critical, 3 unknown -- and so is reading the first line of output as the
// message, up to a "|" that starts performance data. That is what makes the
// thousands of plugins already written usable: a two-line wrapper that calls
// check_something with its arguments is a script this check runs.
//
// What runs is decided on this machine and nowhere else. Gryphon sends a name,
// the name must be a bare file name, and the file must already be in the
// directory the agent was started with. A command in the check's settings
// would make every Gryphon login, and every copy of the access key, a way to
// run anything on every monitored host; a name makes them a way to run what
// the host's administrator already chose to allow. For the same reason the
// agent refuses a directory or script that any user on the machine could
// change, and does not pass its own GWC_ settings -- the access key among
// them -- to what it runs.

// scriptTimeout bounds one run, inside agent.CheckDeadline so a slow script is
// reported as slow rather than as a deadline the agent missed. A variable so a
// test need not wait for it.
var scriptTimeout = 10 * time.Second

const (
	// maxConcurrentScripts bounds how many run at once, so a burst of checks
	// cannot fork without limit.
	maxConcurrentScripts = 4
	// maxScriptOutput is how much of a script's output is kept. The message
	// is its first line; the rest is read and dropped so a chatty script is
	// not blocked on a full pipe.
	maxScriptOutput = 4096
	// maxScriptMessage bounds the message taken from that first line.
	maxScriptMessage = 300
)

type scriptRunner struct {
	dir   string
	slots chan struct{}
}

func newScriptRunner(dir string) *scriptRunner {
	return &scriptRunner{dir: dir, slots: make(chan struct{}, maxConcurrentScripts)}
}

// ValidateScriptsDir reports what is wrong with a directory as the agent's
// scripts directory, or nil. The agent checks it again before every run, so
// this is for refusing a mistake at startup rather than at the first check.
func ValidateScriptsDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("scripts directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scripts directory %s is not a directory", dir)
	}
	if msg := unsafePermissions(info); msg != "" {
		return fmt.Errorf("scripts directory %s %s", dir, msg)
	}
	return nil
}

func scriptUnknown(format string, args ...any) result {
	return result{statusID: agent.StatusUnknown, msg: fmt.Sprintf(format, args...)}
}

func (s *scriptRunner) check(ctx context.Context, params string) result {
	values, err := url.ParseQuery(params)
	if err != nil {
		return scriptUnknown("could not read the check's settings: %v", err)
	}
	if s.dir == "" {
		return scriptUnknown("script checks are turned off on this agent: start it with GWC_SCRIPTS_DIR naming a directory of executables")
	}
	name := strings.TrimSpace(values.Get(agent.ParamScript))
	if !agent.ValidScriptName(name) {
		return scriptUnknown("%q is not a script name: a file name of letters, digits, dots, dashes and underscores", name)
	}
	if err := ValidateScriptsDir(s.dir); err != nil {
		return scriptUnknown("%v, so no script runs from it", err)
	}

	path := filepath.Join(s.dir, name)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return scriptUnknown("no script called %s in %s", name, s.dir)
	}
	if err != nil {
		return scriptUnknown("cannot read script %s: %v", name, err)
	}
	if !info.Mode().IsRegular() {
		return scriptUnknown("script %s is not a regular file", name)
	}
	if msg := unsafePermissions(info); msg != "" {
		return scriptUnknown("script %s %s, so the agent will not run it", name, msg)
	}
	if !executable(info) {
		return scriptUnknown("script %s is not executable (chmod +x it)", name)
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return scriptUnknown("script %s did not start: %d scripts were already running", name, maxConcurrentScripts)
	}

	runCtx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()

	var stdout, stderr cappedBuffer
	cmd := exec.CommandContext(runCtx, path)
	cmd.Dir = s.dir
	cmd.Env = scriptEnv(os.Environ())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A script that leaves a child holding its output open would otherwise
	// keep Wait from returning after the script itself was stopped.
	cmd.WaitDelay = time.Second
	stopWholeGroup(cmd)

	err = cmd.Run()
	if runCtx.Err() != nil {
		if ctx.Err() != nil {
			return scriptUnknown("script %s was stopped: the check was cancelled", name)
		}
		return scriptUnknown("script %s did not finish within %s and was stopped", name, scriptTimeout)
	}

	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		return scriptUnknown("could not run script %s: %v", name, err)
	}

	msg := scriptMessage(stdout.Bytes(), stderr.Bytes())
	switch code {
	case 0:
		return result{statusID: agent.StatusHealthy, msg: orDefault(msg, name+" exited 0 (OK)")}
	case 1:
		return result{statusID: agent.StatusWarning, msg: orDefault(msg, name+" exited 1 (warning)")}
	case 2:
		return result{statusID: agent.StatusProblem, msg: orDefault(msg, name+" exited 2 (critical)")}
	case 3:
		return result{statusID: agent.StatusUnknown, msg: orDefault(msg, name+" exited 3 (unknown)")}
	case -1:
		return scriptUnknown("script %s was killed by a signal", name)
	}
	if msg != "" {
		return scriptUnknown("script %s exited %d, which is not a status (0 to 3): %s", name, code, msg)
	}
	return scriptUnknown("script %s exited %d, which is not a status (0 to 3)", name, code)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// scriptMessage is the first line a script printed, without performance data
// or control characters: stdout's, or stderr's when stdout had nothing.
func scriptMessage(stdout, stderr []byte) string {
	out := stdout
	if len(bytes.TrimSpace(out)) == 0 {
		out = stderr
	}
	line, _, _ := bytes.Cut(bytes.TrimSpace(out), []byte("\n"))
	line, _, _ = bytes.Cut(line, []byte("|"))
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, string(line))
	msg = strings.TrimSpace(msg)
	if runes := []rune(msg); len(runes) > maxScriptMessage {
		msg = string(runes[:maxScriptMessage]) + "…"
	}
	return msg
}

// scriptEnv is the agent's environment less its own settings. GWC_KEY is the
// access key, and a script has no business with it; the rest go too, so that
// no future setting has to remember to.
func scriptEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "GWC_") {
			out = append(out, kv)
		}
	}
	return out
}

// cappedBuffer keeps the first maxScriptOutput bytes written to it and
// accepts, without keeping, the rest.
type cappedBuffer struct{ buf bytes.Buffer }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxScriptOutput - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }
