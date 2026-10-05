// Command client is the Gryphon client agent as a headless binary for
// servers. The agent itself is pkg/clientagent; this wraps it in the
// configuration a server expects -- defaults, then GWC_* environment
// variables, then flags -- and runs it until told to stop. It connects to
// Gryphon; nothing listens.
//
// `gryphon-agent enrol` takes the token from the host's page in Gryphon,
// checks it, saves it and starts the agent; see enrol.go.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/clientagent"
	"github.com/gocodedotca/gryphon-agent/pkg/envconf"
	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

type config struct {
	agent     clientagent.Config
	logFormat string
	// showVersion asks for the build to be printed instead of running.
	showVersion bool
}

// loadConfig resolves configuration: defaults, then GWC_* environment
// variables, then flags — the same precedence the server uses.
//
// Every variable also honours the GWC_NAME_FILE twin that the server does, so
// the agent can be handed a Docker or Kubernetes secret — both deliver those as
// files, never as environment variables.
func loadConfig(args []string, getenv func(string) string) (config, error) {
	// GWC_KEY_FILE=- is the token on standard input, which is how the
	// systemd unit hands it over: systemd opens /etc/gryphon/agent_key as
	// root and passes it in, so the agent's own user -- and every script it
	// runs as that user -- has no path to the file. Read here, once, and then
	// replaced with the token itself for the resolver below.
	if getenv("GWC_KEY_FILE") == keyFromStdin {
		key, err := readKeyFrom(keyStdin)
		if err != nil {
			return config{}, fmt.Errorf("GWC_KEY_FILE=-: reading the key from standard input: %w", err)
		}
		getenv = withKey(getenv, key)
	}
	env := envconf.NewResolver("GWC_", getenv)
	envOr := func(name, def string) string {
		if v, ok := env.Lookup(name); ok && v != "" {
			return v
		}
		return def
	}
	// Read through the resolver rather than envOr, so GWC_ALLOW_PUBLIC_TARGETS
	// gets the file twin and the "that is not a boolean" failure every other
	// setting gets. It is the flag's default, so a flag still wins.
	var allowPublicTargets, allowInsecureServer bool
	env.Bool("ALLOW_PUBLIC_TARGETS", &allowPublicTargets)
	env.Bool("ALLOW_INSECURE_SERVER", &allowInsecureServer)

	fs := flag.NewFlagSet("gryphon-agent", flag.ContinueOnError)
	server := fs.String("server", envOr("SERVER", clientagent.DefaultServer),
		"the Gryphon to connect to")
	insecure := fs.Bool("allow-insecure-server", allowInsecureServer,
		"allow an http:// server: for development, or an installation reached only across its own network")
	logFormat := fs.String("logformat", envOr("LOG_FORMAT", "text"), "log format: text or json")
	dockerSocket := fs.String("docker-socket", envOr("DOCKER_SOCKET", clientagent.DefaultDockerSocket),
		"the Docker Engine's socket, for the container and Swarm checks")
	scriptsDir := fs.String("scripts-dir", envOr("SCRIPTS_DIR", ""),
		"directory of executables the script checks may run by name; empty turns script checks off")
	watchDirs := fs.String("watch-dirs", envOr("WATCH_DIRS", ""),
		"folders the file-age checks may look in, separated as PATH is; empty turns file checks off")
	allowPublic := fs.Bool("allow-public-targets", allowPublicTargets,
		"let the network and database checks dial the public internet; off by default, so the agent reaches its own network only")
	maxConcurrent := fs.Int("max-concurrent", envInt(env, "MAX_CONCURRENT", clientagent.DefaultMaxConcurrent),
		"how many checks may run at once; past it the agent answers that it is busy")
	showVersion := fs.Bool("version", false, "print the build and exit")

	// The token comes from GWC_KEY or GWC_KEY_FILE and deliberately has no
	// flag: a flag is readable by every user on the machine through ps.
	key, _ := env.Lookup("KEY")

	// There are deliberately no threshold flags; see clientagent.Config.
	c := config{}

	// A named secret file that cannot be read is a startup failure, not a
	// silent fall-back to the default.
	if err := env.Err(); err != nil {
		return c, err
	}

	if err := fs.Parse(args); err != nil {
		return c, err
	}

	c.agent.Server = strings.TrimSpace(*server)
	c.agent.AllowInsecureServer = *insecure
	c.agent.DockerSocket = *dockerSocket
	c.agent.ScriptsDir = strings.TrimSpace(*scriptsDir)
	c.agent.WatchDirs = clientagent.SplitWatchDirs(*watchDirs)
	c.agent.AllowPublicTargets = *allowPublic
	c.agent.MaxConcurrent = *maxConcurrent
	c.showVersion = *showVersion
	if c.showVersion {
		return c, nil
	}

	switch *logFormat {
	case "text", "json":
		c.logFormat = *logFormat
	default:
		return c, fmt.Errorf("log format must be text or json, not %s", *logFormat)
	}

	if c.agent.ScriptsDir != "" {
		if err := clientagent.ValidateScriptsDir(c.agent.ScriptsDir); err != nil {
			return c, fmt.Errorf("GWC_SCRIPTS_DIR: %w", err)
		}
	}
	if err := clientagent.ValidateWatchDirs(c.agent.WatchDirs); err != nil {
		return c, fmt.Errorf("GWC_WATCH_DIRS: %w", err)
	}

	if _, err := clientagent.ConnectURL(c.agent.Server, c.agent.AllowInsecureServer); err != nil {
		return c, fmt.Errorf("GWC_SERVER: %w", err)
	}

	c.agent.Key = strings.TrimSpace(key)
	if c.agent.Key == "" {
		return c, errors.New("no token: copy one from the host's page in Gryphon and run: gryphon-agent enrol")
	}
	if err := clientagent.ValidateKey(c.agent.Key); err != nil {
		return c, fmt.Errorf("the token is not usable: %w (copy it again from the host's page in Gryphon and run: gryphon-agent enrol)", err)
	}

	return c, nil
}

// keyFromStdin is the GWC_KEY_FILE value that means standard input.
const keyFromStdin = "-"

// keyStdin is where GWC_KEY_FILE=- reads from; a variable so a test can hand
// it a key.
var keyStdin io.Reader = os.Stdin

// readKeyFrom reads a key from r: the first line, trimmed, and no more than a
// key could be, so a mistaken pipe cannot make the agent read without end.
func readKeyFrom(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxKeyInput))
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line), nil
}

// maxKeyInput bounds what readKeyFrom reads: a key of the longest length the
// agent accepts, with room for a line ending.
const maxKeyInput = 4096

// withKey is getenv with the key read from standard input standing in for
// GWC_KEY, and GWC_KEY_FILE gone so the resolver does not try to open "-".
func withKey(getenv func(string) string, key string) func(string) string {
	return func(name string) string {
		switch name {
		case "GWC_KEY":
			return key
		case "GWC_KEY_FILE":
			return ""
		}
		return getenv(name)
	}
}

func main() {
	// Before anything else, and before any script can run: a process its own
	// user cannot inspect. See harden_linux.go.
	if err := hardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot protect the agent's memory from its scripts:", err)
		os.Exit(1)
	}
	// "service install" and "service uninstall" manage the Windows service;
	// see service_windows.go. "enrol" gives the agent its token; enrol.go.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "service":
			os.Exit(serviceCommand(os.Args[2:]))
		case "enrol", "enroll":
			os.Exit(enrolCommand(os.Args[2:]))
		}
	}
	// Started by the Windows service manager rather than from a console.
	if isService() {
		runService()
		return
	}

	cfg, err := loadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The key has been read; the file it came from is closed, so nothing the
	// agent starts later could find it through this process.
	if os.Getenv("GWC_KEY_FILE") == keyFromStdin {
		if err := releaseStdin(); err != nil {
			fmt.Fprintln(os.Stderr, "closing standard input:", err)
			os.Exit(1)
		}
	}

	if cfg.showVersion {
		fmt.Println(version.Version())
		return
	}

	log := newLogger(os.Stdout, cfg.logFormat, true)
	ag, err := startAgent(cfg, log)
	if err != nil {
		os.Exit(1)
	}

	// Run until told to stop, then let the checks in flight answer.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	log.Info("shutting down", "signal", sig.String())
	stopAgent(ag, log)
}

// newLogger logs in the configured format. withTime is false where the
// destination stamps each line itself, as the Windows event log does.
func newLogger(w io.Writer, format string, withTime bool) *slog.Logger {
	opts := &slog.HandlerOptions{}
	if !withTime {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// startAgent starts connecting, logging why when it cannot. From then on the
// agent reconnects on its own and logs as it does.
func startAgent(cfg config, log *slog.Logger) (*clientagent.Connector, error) {
	ag := clientagent.NewConnector(cfg.agent, log, nil)
	if err := ag.Start(); err != nil {
		log.Error("cannot start", "error", err)
		return nil, err
	}
	return ag, nil
}

// stopAgent disconnects, giving the checks in flight time to answer.
func stopAgent(ag *clientagent.Connector, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := ag.Stop(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.Error("shutdown", "error", err)
	}
}

// shutdownGrace is how long stopAgent waits for checks in flight: each has
// agent.CheckDeadline, and the close a few seconds more.
const shutdownGrace = 20 * time.Second

// envInt reads a whole number from the environment, or def when it is unset;
// a value that is not a number is reported as the flag's own parse error
// would be.
func envInt(env *envconf.Resolver, name string, def int) int {
	v, ok := env.Lookup(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 {
		return def
	}
	return n
}
