package clientagent

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
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
		return phrase.Errorf("scripts directory: {err}", "err", err)
	}
	if !info.IsDir() {
		return phrase.Errorf("scripts directory {dir} is not a directory", "dir", dir)
	}
	// The problem is a phrase of its own ("is writable by every user on
	// this machine"), translated with the sentence it is put in.
	if problem := unsafePermissions(dir, info); problem != "" {
		return phrase.Errorf("scripts directory {dir} {problem}", "dir", dir, "problem", problem)
	}
	return nil
}

// scriptUnknown answers unknown with a message written with phrase.T at the
// call site.
func scriptUnknown(msg string) result {
	return result{statusID: agent.StatusUnknown, msg: msg}
}

func (s *scriptRunner) check(ctx context.Context, params string) result {
	values, err := url.ParseQuery(params)
	if err != nil {
		return unreadableSettings(err)
	}
	if s.dir == "" {
		return scriptUnknown(phrase.T("script checks are turned off on this agent: start it with GWC_SCRIPTS_DIR naming a directory of executables"))
	}
	name := strings.TrimSpace(values.Get(agent.ParamScript))
	if !agent.ValidScriptName(name) {
		return scriptUnknown(phrase.T("{name} is not a script name: a file name of letters, digits, dots, dashes and underscores",
			"name", strconv.Quote(name)))
	}
	if err := ValidateScriptsDir(s.dir); err != nil {
		return scriptUnknown(phrase.T("{err}, so no script runs from it", "err", err))
	}

	path := filepath.Join(s.dir, name)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return scriptUnknown(phrase.T("no script called {name} in {dir}", "name", name, "dir", s.dir))
	}
	if err != nil {
		return scriptUnknown(phrase.T("cannot read script {name}: {err}", "name", name, "err", err))
	}
	if !info.Mode().IsRegular() {
		return scriptUnknown(phrase.T("script {name} is not a regular file", "name", name))
	}
	if problem := unsafePermissions(path, info); problem != "" {
		return scriptUnknown(phrase.T("script {name} {problem}, so the agent will not run it", "name", name, "problem", problem))
	}
	if !executable(path, info) {
		return scriptUnknown(phrase.T("script {name} is not executable ({hint})", "name", name, "hint", notExecutableHint))
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return scriptUnknown(phrase.T("script {name} did not start: {n} scripts were already running", "name", name, "n", maxConcurrentScripts))
	}

	runCtx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()

	var stdout, stderr cappedBuffer
	cmd := scriptCommand(runCtx, path)
	cmd.Dir = s.dir
	cmd.Env = scriptEnv(os.Environ())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A script that leaves a child holding its output open would otherwise
	// keep Wait from returning after the script itself was stopped.
	cmd.WaitDelay = time.Second

	// Run, stopping what the script started as well as the script when the
	// time is up: a process group on Unix, a job object on Windows.
	err = runScript(cmd)
	if runCtx.Err() != nil {
		if ctx.Err() != nil {
			return scriptUnknown(phrase.T("script {name} was stopped: the check was cancelled", "name", name))
		}
		return scriptUnknown(phrase.T("script {name} did not finish within {timeout} and was stopped", "name", name, "timeout", scriptTimeout))
	}

	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		return scriptUnknown(phrase.T("could not run script {name}: {err}", "name", name, "err", err))
	}

	msg := scriptMessage(stdout.Bytes(), stderr.Bytes())
	switch code {
	case 0:
		return result{statusID: agent.StatusHealthy, msg: orDefault(msg, phrase.T("{name} exited 0 (OK)", "name", name))}
	case 1:
		return result{statusID: agent.StatusWarning, msg: orDefault(msg, phrase.T("{name} exited 1 (warning)", "name", name))}
	case 2:
		return result{statusID: agent.StatusProblem, msg: orDefault(msg, phrase.T("{name} exited 2 (critical)", "name", name))}
	case 3:
		return result{statusID: agent.StatusUnknown, msg: orDefault(msg, phrase.T("{name} exited 3 (unknown)", "name", name))}
	case -1:
		return scriptUnknown(phrase.T("script {name} was killed by a signal", "name", name))
	}
	if msg != "" {
		return scriptUnknown(phrase.T("script {name} exited {code}, which is not a status (0 to 3): {output}", "name", name, "code", code, "output", msg))
	}
	return scriptUnknown(phrase.T("script {name} exited {code}, which is not a status (0 to 3)", "name", name, "code", code))
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
