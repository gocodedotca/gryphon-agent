// Package clientagent is the Gryphon client agent: it runs on a monitored
// host, connects to Gryphon, and answers the checks Gryphon sends -- what
// network checks cannot see from outside (disk, memory, CPU, system load,
// local databases) and the network checks themselves (HTTP, HTTPS, ping), run
// from inside the network, where services the Gryphon server cannot reach
// are. On a Docker node it also asks the Engine about containers, and on a
// Swarm manager about services.
//
// The agent only ever dials out (see Connector), speaking the protocol in
// pkg/agent; nothing listens on the host. cmd/client wraps it as a headless
// binary for servers and cmd/client-mac as a menu bar app, and the two differ
// only in where their configuration comes from.
package clientagent

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

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
	// Key is the token Gryphon issued for this host, which the agent
	// presents when it connects. Without one it does not start.
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
	// holds a copy of the token. See reach.go.
	//
	// Turning it on is for the operator who genuinely wants a check on a
	// public service run from this host: a bank of egress checks, an
	// outbound-firewall test. It is their decision, made here, on their own
	// machine.
	AllowPublicTargets bool

	// Server is the Gryphon the agent connects to, DefaultServer when empty.
	// Changed for development and for a self-hosted installation; a customer
	// never sets it.
	Server string
	// AllowInsecureServer lets Server be http:// rather than https://: for a
	// server on the developer's own machine, or a self-hosted installation
	// that only ever talks across its own LAN. Off, the token and every
	// check's settings would cross the network in the clear, so the agent
	// refuses to start.
	AllowInsecureServer bool
}

// ErrNoKey is returned by Start when the configuration has no token.
var ErrNoKey = agent.ErrNoKey

// ErrRunning is returned by Start when the agent is already running.
var ErrRunning = errors.New("agent is already running")

// ValidateKey reports what is wrong with an access key, or nil.
func ValidateKey(key string) error { return agent.ValidateKey(key) }

// GenerateKey returns a new random access key.
func GenerateKey() (string, error) { return agent.GenerateKey() }

// withDefaults returns a copy of c with its defaults filled in.
func (c Config) withDefaults() Config {
	c.Key = strings.TrimSpace(c.Key)
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.DockerSocket == "" {
		c.DockerSocket = DefaultDockerSocket
	}
	c.Server = strings.TrimSpace(c.Server)
	if c.Server == "" {
		c.Server = DefaultServer
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
