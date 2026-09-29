// Package clientagent is the Gryphon client agent: a small HTTP service that
// runs on a monitored host and measures what network checks cannot see from
// outside — disk, memory, CPU, system load, and local databases — and runs the
// network checks themselves (HTTP, HTTPS, ping) from inside the network, where
// services the Gryphon server cannot reach are. On a Docker node it also asks
// the Engine about containers, and on a Swarm manager about services.
//
// It answers to the paths pkg/checks.AgentChecker posts to, speaking the wire
// protocol in pkg/agent. The package is the agent; cmd/client wraps it as a
// headless binary for servers and cmd/client-mac as a menu bar app, and the
// two differ only in where their configuration comes from.
package clientagent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// DefaultAddr is where the agent listens when nothing says otherwise.
const DefaultAddr = ":6001"

// DefaultMaxConcurrent is how many checks run at once unless told otherwise.
const DefaultMaxConcurrent = 32

// MinKeyLength is the shortest access key the agent will run with.
const MinKeyLength = agent.MinKeyLength

// Config is what the agent needs to run. There are deliberately no threshold
// settings: the agent measures, the server decides. Thresholds live per host
// service in the database, where they can be tuned for one node from the
// interface -- a setting here would be a second place for alerting policy to
// live, and the whole point of the sensor protocol is that there is only one.
type Config struct {
	// Addr is the listen address, ":6001" by default. Behind a reverse proxy
	// on the same machine, "127.0.0.1:6001" keeps the agent off the network.
	Addr string
	// Key is the pre-shared access key. Every request must present it as
	// "Authorization: Bearer <key>", and Gryphon sends the one saved on the
	// host.
	//
	// It replaces an allow list of caller addresses. The list was matched
	// against the connection's remote address, so behind a reverse proxy --
	// the recommended deployment -- the address to allow was the proxy's, and
	// with the proxy on the same machine that was loopback, which was always
	// allowed: the agent was open to anything the proxy would forward. It was
	// also the setting people got wrong. A key is the same on either side of a
	// proxy and says who is calling rather than where from.
	//
	// There is no exemption for loopback, for exactly the proxy reason, and no
	// way to run without a key.
	Key string
	// DockerSocket is where the Docker Engine listens, for the container and
	// Swarm checks; DefaultDockerSocket when empty. The agent's user must be
	// able to open it, which on Linux means the docker group. Nothing else
	// the agent does touches it, so on a node without Docker the setting is
	// inert and only those checks answer unknown.
	DockerSocket string
	// ScriptsDir is the directory script checks run executables from, by
	// file name. Empty turns script checks off, which is the default: what
	// may run on this machine is its administrator's decision, made here,
	// and never something Gryphon can send. See checks-script.go.
	ScriptsDir string
	// WatchDirs are the folders file-age checks may look in: the check's
	// path must be inside one of them. Empty turns file checks off, which is
	// the default, for the same reason as ScriptsDir: which of this
	// machine's files Gryphon may ask about is its administrator's decision.
	// See checks-file.go.
	WatchDirs []string
	// PreviousKey is a second key accepted alongside Key, for rotation: the
	// agent is restarted with the new key as Key and the old one here, the
	// host in Gryphon is given the new key, and the old one is dropped on
	// the next restart. Empty means only Key is accepted.
	PreviousKey string
	// MaxConcurrent caps how many checks run at once, DefaultMaxConcurrent
	// when zero. A burst of checks against a host with a stuck disk used to
	// pile up goroutines without limit; past the cap the agent answers
	// unknown and says it is busy.
	MaxConcurrent int
	// AllowPublicTargets lets the network and database checks dial the public
	// internet. Off by default, so the agent reaches its own network and
	// nothing else.
	//
	// The address those checks dial is one somebody typed into a form on the
	// Gryphon server, and a TCP send/expect check writes a line and reports
	// what came back. Left open, that makes the agent a port scanner and a
	// relay onto the internet, running from inside the network it was
	// installed to watch -- and the machine best placed to refuse is this one,
	// because the refusal then holds whatever the server sends and whoever
	// holds a copy of the key. See reach.go.
	//
	// Turning it on is for the operator who genuinely wants a check on a
	// public service run from this host: a bank of egress checks, an
	// outbound-firewall test. It is their decision, made here, on their own
	// machine.
	AllowPublicTargets bool
}

// ErrNoKey is returned by Start when the configuration has no key.
var ErrNoKey = agent.ErrNoKey

// ValidateKey reports what is wrong with an access key, or nil.
func ValidateKey(key string) error { return agent.ValidateKey(key) }

// GenerateKey returns a new random access key.
func GenerateKey() (string, error) { return agent.GenerateKey() }

// withDefaults returns a copy of c with the default address filled in.
func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if !strings.Contains(c.Addr, ":") {
		c.Addr = ":" + c.Addr
	}
	c.Key = strings.TrimSpace(c.Key)
	c.PreviousKey = strings.TrimSpace(c.PreviousKey)
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.DockerSocket == "" {
		c.DockerSocket = DefaultDockerSocket
	}
	c.ScriptsDir = strings.TrimSpace(c.ScriptsDir)
	var dirs []string
	for _, d := range c.WatchDirs {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, filepath.Clean(d))
		}
	}
	c.WatchDirs = dirs
	return c
}

// Agent is the running service: a listener and the HTTP server behind it. It
// can be started and stopped repeatedly, which is what an on/off switch needs.
type Agent struct {
	cfg Config
	log *slog.Logger

	mu   sync.Mutex
	srv  *http.Server
	addr net.Addr
	// done is closed when the server goroutine returns; Stop waits for it so
	// that a Start straight after a Stop cannot race the old listener for the
	// port.
	done chan struct{}
}

// ErrRunning is returned by Start when the agent is already listening.
var ErrRunning = errors.New("agent is already running")

// New makes an agent for cfg. Nothing listens until Start.
func New(cfg Config, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Agent{cfg: cfg.withDefaults(), log: log}
}

// writeTimeout bounds the whole of a check request, reading included. Every
// check answers within agent.CheckDeadline, so this only has to leave room
// beyond that to decode the request and write the answer.
const writeTimeout = 20 * time.Second

// Start binds the port and begins serving. The bind is synchronous: a port
// already in use is an error the caller sees here, not a log line from a
// goroutine, because a menu that says "on" while nothing is listening is
// worse than one that says why it could not turn on. So is a missing or
// unusable key, which is checked before anything listens.
func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv != nil {
		return ErrRunning
	}
	if err := ValidateKey(a.cfg.Key); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", a.cfg.Addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           newHandlers(a.cfg, a.log).routes(),
		IdleTimeout:       30 * time.Second,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      writeTimeout,
	}
	done := make(chan struct{})
	a.srv, a.addr, a.done = srv, ln.Addr(), done

	a.log.Info("agent listening", "addr", ln.Addr().String())
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("agent stopped", "error", err)
		}
	}()
	return nil
}

// Stop closes the listener and drains in-flight checks, waiting up to the
// context's deadline. Stopping an agent that is not running is not an error.
func (a *Agent) Stop(ctx context.Context) error {
	a.mu.Lock()
	srv, done := a.srv, a.done
	a.srv, a.addr, a.done = nil, nil, nil
	a.mu.Unlock()
	if srv == nil {
		return nil
	}

	a.log.Info("agent stopping")
	err := srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		// The listener is closed either way; the slow check is abandoned.
		err = nil
	}
	<-done
	return err
}

// Addr is the address the agent is listening on, or nil when it is not.
// Useful when Config.Addr asked for port 0.
func (a *Agent) Addr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addr
}

// Running reports whether the agent is listening.
func (a *Agent) Running() bool {
	return a.Addr() != nil
}
