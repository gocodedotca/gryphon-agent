// Command client is the Gryphon client agent as a headless binary for
// servers. The agent itself is pkg/clientagent; this wraps it in the
// configuration a server expects -- defaults, then GWC_* environment
// variables, then flags -- and runs it until told to stop.
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
	// genKey asks for a new key to be printed instead of running the agent.
	genKey bool
	// showVersion asks for the build to be printed instead.
	showVersion bool
}

// loadConfig resolves configuration: defaults, then GWC_* environment
// variables, then flags — the same precedence the server uses.
//
// Every variable also honours the GWC_NAME_FILE twin that the server does, so
// the agent can be handed a Docker or Kubernetes secret — both deliver those as
// files, never as environment variables.
func loadConfig(args []string, getenv func(string) string) (config, error) {
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
	var allowPublicTargets bool
	env.Bool("ALLOW_PUBLIC_TARGETS", &allowPublicTargets)

	fs := flag.NewFlagSet("gowatcher-client", flag.ContinueOnError)
	port := fs.String("port", envOr("PORT", clientagent.DefaultAddr),
		"address to listen on: :6001, or 127.0.0.1:6001 behind a reverse proxy on this machine")
	logFormat := fs.String("logformat", envOr("LOG_FORMAT", "text"), "log format: text or json")
	dockerSocket := fs.String("docker-socket", envOr("DOCKER_SOCKET", clientagent.DefaultDockerSocket),
		"the Docker Engine's socket, for the container and Swarm checks")
	scriptsDir := fs.String("scripts-dir", envOr("SCRIPTS_DIR", ""),
		"directory of executables the script checks may run by name; empty turns script checks off")
	allowPublic := fs.Bool("allow-public-targets", allowPublicTargets,
		"let the network and database checks dial the public internet; off by default, so the agent reaches its own network only")
	maxConcurrent := fs.Int("max-concurrent", envInt(env, "MAX_CONCURRENT", clientagent.DefaultMaxConcurrent),
		"how many checks may run at once; past it the agent answers that it is busy")
	genKey := fs.Bool("genkey", false, "print a new access key and exit")
	showVersion := fs.Bool("version", false, "print the build and exit")

	// The access key comes from GWC_KEY or GWC_KEY_FILE and deliberately has no
	// flag: a flag is readable by every user on the machine through ps.
	// GWC_KEY_PREVIOUS is the key being rotated out, accepted alongside it.
	key, _ := env.Lookup("KEY")
	previousKey, _ := env.Lookup("KEY_PREVIOUS")

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

	c.agent.Addr = *port
	c.agent.DockerSocket = *dockerSocket
	c.agent.ScriptsDir = strings.TrimSpace(*scriptsDir)
	c.agent.AllowPublicTargets = *allowPublic
	c.agent.MaxConcurrent = *maxConcurrent
	c.agent.PreviousKey = strings.TrimSpace(previousKey)
	c.genKey = *genKey
	c.showVersion = *showVersion
	if c.genKey || c.showVersion {
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

	c.agent.Key = strings.TrimSpace(key)
	if err := clientagent.ValidateKey(c.agent.Key); err != nil {
		return c, fmt.Errorf("GWC_KEY: %w (generate one with -genkey, then set GWC_KEY or GWC_KEY_FILE)", err)
	}

	return c, nil
}

func main() {
	// "service install" and "service uninstall" manage the Windows service;
	// see service_windows.go.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(serviceCommand(os.Args[2:]))
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

	if cfg.showVersion {
		fmt.Println(version.Version())
		return
	}
	if cfg.genKey {
		key, err := clientagent.GenerateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(key)
		return
	}

	log := newLogger(os.Stdout, cfg.logFormat, true)
	ag, err := startAgent(cfg, log)
	if err != nil {
		os.Exit(1)
	}

	// Serve until told to stop, then drain in-flight checks.
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

// startAgent starts listening, logging why when it cannot.
func startAgent(cfg config, log *slog.Logger) (*clientagent.Agent, error) {
	log.Info("starting Gryphon client agent", "version", version.Version())
	ag := clientagent.New(cfg.agent, log)
	if err := ag.Start(); err != nil {
		log.Error("cannot start", "error", err)
		return nil, err
	}
	return ag, nil
}

// stopAgent stops listening and gives in-flight checks ten seconds to finish.
func stopAgent(ag *clientagent.Agent, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := ag.Stop(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.Error("shutdown", "error", err)
	}
}

// shutdownGrace is how long stopAgent waits for checks in flight.
const shutdownGrace = 10 * time.Second

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
