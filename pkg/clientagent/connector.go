package clientagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

// DefaultServer is the Gryphon an agent connects to unless told otherwise.
const DefaultServer = agent.DefaultServer

// ConnectURL is the WebSocket address an agent configured with server dials.
// An empty server is DefaultServer. It must be https://, or http:// when
// allowInsecure says the installation chose that; a base path is kept, so a
// server mounted under one is reachable.
func ConnectURL(server string, allowInsecure bool) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		server = DefaultServer
	}
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("server %q is not an address: %w", server, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		u.Scheme = "wss"
	case "http":
		if !allowInsecure {
			return "", fmt.Errorf("server %q is http://: the token and every check's settings would cross the network in the clear (set GWC_ALLOW_INSECURE_SERVER to allow it on a network you trust)", server)
		}
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("server %q must be an https:// address", server)
	}
	if u.Host == "" {
		return "", fmt.Errorf("server %q has no host name", server)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server %q must be a plain address, with no user name, query or fragment", server)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + agent.ConnectPath
	u.RawPath = ""
	return u.String(), nil
}

// ConnState is where a Connector is in its life.
type ConnState int

const (
	// Stopped: not started, or stopped.
	Stopped ConnState = iota
	// Connecting: dialling the server.
	Connecting
	// Connected: the connection is open and checks are being answered.
	Connected
	// Retrying: the last attempt failed or the connection ended; the next
	// attempt is at RetryAt.
	Retrying
	// Refused: the server refused the token, or does not speak this agent's
	// protocol. Retried, but slowly, because it will go on refusing until
	// somebody changes something.
	Refused
)

func (s ConnState) String() string {
	switch s {
	case Stopped:
		return "stopped"
	case Connecting:
		return "connecting"
	case Connected:
		return "connected"
	case Retrying:
		return "retrying"
	case Refused:
		return "refused"
	}
	return fmt.Sprintf("ConnState(%d)", int(s))
}

// ConnStatus is what a Connector reports about itself, for a log line or a
// menu's status line.
type ConnStatus struct {
	State ConnState
	// Server is the address being connected to, as configured.
	Server string
	// Since is when this state began.
	Since time.Time
	// Err is why the last attempt failed or the last connection ended, in
	// Retrying and Refused.
	Err error
	// RetryAt is when the next attempt is made, in Retrying and Refused.
	RetryAt time.Time
}

// ErrTokenRefused is the server refusing the agent's token: it is wrong, was
// replaced, or its host was deleted.
var ErrTokenRefused = errors.New("the server refused this agent's token")

// ErrIncompatible is a server that does not speak this agent's protocol: one
// of the two needs updating.
var ErrIncompatible = errors.New("the server does not speak this agent's protocol; update the agent")

// How the Connector paces itself. Variables so that tests need not wait.
var (
	// minBackoff and maxBackoff bound the wait after a failed attempt, which
	// doubles from the one to the other. The wait is drawn at random from
	// zero up to that bound ("full jitter"), so a thousand agents that lost
	// the server together do not all come back in the same second.
	minBackoff = time.Second
	maxBackoff = time.Minute
	// refusedBackoff is the wait after a refusal. Long, because nothing on
	// this side will change the answer: a deleted host's agent is not to
	// knock every minute forever.
	refusedBackoff = 5 * time.Minute
	// goingAwayJitter bounds the wait after a server closed the connection
	// because it is shutting down -- a deploy. Another replica is already
	// there, so the agent goes straight back, spread over a few seconds.
	goingAwayJitter = 5 * time.Second
	// stableAfter is how long a connection must have lasted for its loss to
	// start the backoff over, rather than continue it.
	stableAfter = time.Minute
	// connectTimeout bounds one attempt to connect, handshake included.
	connectTimeout = 15 * time.Second
	// frameWriteTimeout bounds writing one frame. A connection that cannot
	// take a frame in that long is not one checks can be answered on.
	frameWriteTimeout = 10 * time.Second
)

// Connector is the agent: it connects to Gryphon, keeps the connection open,
// and answers the checks Gryphon sends down it. It reconnects on its own,
// for as long as it runs, and can be started and stopped repeatedly, which is
// what an on/off switch needs.
//
// Nothing listens: the agent only ever dials out, so the host it watches needs
// no open port, no certificate and no reverse proxy.
type Connector struct {
	cfg      Config
	log      *slog.Logger
	onStatus func(ConnStatus)

	mu     sync.Mutex
	status ConnStatus
	cancel context.CancelFunc
	// done is closed when the run started by Start has finished; Stop waits
	// for it.
	done chan struct{}
}

// NewConnector makes an agent for cfg. Nothing connects until Start.
//
// onStatus, when not nil, is called with every change of state, from the
// Connector's own goroutine: it must not block, and must not call Start or
// Stop.
func NewConnector(cfg Config, log *slog.Logger, onStatus func(ConnStatus)) *Connector {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cfg = cfg.withDefaults()
	return &Connector{
		cfg:      cfg,
		log:      log,
		onStatus: onStatus,
		status:   ConnStatus{State: Stopped, Server: cfg.Server},
	}
}

// Start checks the configuration and begins connecting. A missing token or an
// unusable server address is an error here, before anything is attempted: an
// on/off switch that says "on" while nothing can ever connect is worse than
// one that says why. Everything after -- the server being down, a refusal -- is
// reported through the status and retried.
func (c *Connector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return ErrRunning
	}
	if err := ValidateKey(c.cfg.Key); err != nil {
		return err
	}
	target, err := ConnectURL(c.cfg.Server, c.cfg.AllowInsecureServer)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.cancel, c.done = cancel, done
	c.log.Info("agent starting", "server", c.cfg.Server, "version", version.Version())

	// One set of handlers for the life of this run, not one per connection:
	// a check still stuck from a connection that dropped holds its slot until
	// it returns, and that must count against the next connection's cap.
	h := newHandlers(c.cfg, c.log)
	go func() {
		defer close(done)
		c.loop(ctx, h, target)
	}()
	return nil
}

// Stop disconnects, after letting the checks in progress answer -- each is
// bounded by agent.CheckDeadline -- and waits for that up to ctx's deadline.
// Stopping an agent that is not running is not an error.
func (c *Connector) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done = nil, nil
	c.mu.Unlock()
	if cancel == nil {
		return nil
	}

	c.log.Info("agent stopping")
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// The connection is being closed either way; the slow check is
		// abandoned.
		return nil
	}
}

// Running reports whether the agent has been started and not stopped. It says
// nothing about whether it is connected; Status does.
func (c *Connector) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancel != nil
}

// Status reports where the agent is.
func (c *Connector) Status() ConnStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *Connector) setStatus(state ConnState, err error, retryAt time.Time) {
	st := ConnStatus{State: state, Server: c.cfg.Server, Since: time.Now(), Err: err, RetryAt: retryAt}
	c.mu.Lock()
	c.status = st
	c.mu.Unlock()
	if c.onStatus != nil {
		c.onStatus(st)
	}
}

// loop connects, and reconnects, until ctx ends.
func (c *Connector) loop(ctx context.Context, h *handlers, target string) {
	attempt := 0
	for {
		c.setStatus(Connecting, nil, time.Time{})
		lasted, err := c.session(ctx, h, target)
		if ctx.Err() != nil {
			c.setStatus(Stopped, nil, time.Time{})
			return
		}

		if websocket.CloseStatus(err) == agent.CloseRevoked {
			// Said on an open connection rather than at the door, but the
			// same thing: the next attempt with this token is refused.
			err = fmt.Errorf("%w: it was replaced, or its host deleted", ErrTokenRefused)
		}

		state, wait := Retrying, time.Duration(0)
		var busy *busyError
		switch {
		case errors.As(err, &busy):
			// As long as the server asked, and up to as long again, so that
			// the agents it turned away together do not return together.
			wait = busy.wait + rand.N(busy.wait+1)
			c.log.Info("server is busy; waiting as asked", "server", c.cfg.Server, "retry_in", wait)
		case errors.Is(err, ErrTokenRefused), errors.Is(err, ErrIncompatible):
			state, wait = Refused, refusedBackoff
			attempt = 0
			c.log.Error("server refused the agent", "server", c.cfg.Server, "error", err, "retry_in", wait)
		case websocket.CloseStatus(err) == websocket.StatusGoingAway:
			// A deploy: another replica is already up.
			wait = rand.N(goingAwayJitter + 1)
			attempt = 0
			c.log.Info("server is restarting; reconnecting", "server", c.cfg.Server, "retry_in", wait)
		default:
			if lasted >= stableAfter {
				attempt = 0
			}
			wait = backoff(attempt)
			attempt++
			c.log.Warn("not connected", "server", c.cfg.Server, "error", err, "retry_in", wait)
		}

		c.setStatus(state, err, time.Now().Add(wait))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.setStatus(Stopped, nil, time.Time{})
			return
		case <-timer.C:
		}
	}
}

// backoff is the wait before attempt n (from zero) after failures in a row:
// up to minBackoff doubled n times, capped at maxBackoff, drawn at random.
func backoff(n int) time.Duration {
	bound := maxBackoff
	if n < 30 {
		if b := minBackoff << n; b > 0 && b < maxBackoff {
			bound = b
		}
	}
	return rand.N(bound + 1)
}

// session is one connection: dial, say hello, answer frames until it ends.
// It reports how long it was connected (zero if it never was) and why it
// ended.
func (c *Connector) session(ctx context.Context, h *handlers, target string) (time.Duration, error) {
	conn, err := dial(ctx, target, c.cfg.Key)
	if err != nil {
		return 0, err
	}

	// The connection's own context, not ctx: a read whose context is
	// cancelled drops the connection without a close frame. Stopping is
	// done below, properly, once the checks in progress have answered.
	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var flights inFlight
	stopping := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			close(stopping)
			select {
			case <-flights.drain():
			case <-sctx.Done():
			}
			_ = conn.Close(websocket.StatusNormalClosure, "agent stopping")
		case <-sctx.Done():
		}
	}()

	if err := writeFrame(sctx, conn, helloFrame(h)); err != nil {
		conn.CloseNow()
		return 0, err
	}

	connectedAt := time.Now()
	c.setStatus(Connected, nil, time.Time{})
	c.log.Info("connected", "server", c.cfg.Server)

	go keepalive(sctx, conn, c.log)

	for {
		typ, data, err := conn.Read(sctx)
		if err != nil {
			return time.Since(connectedAt), err
		}
		if typ != websocket.MessageText {
			c.log.Warn("ignored a binary frame from the server")
			continue
		}
		var f agent.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			c.log.Warn("ignored a frame that is not JSON", "error", err)
			continue
		}

		switch f.Type {
		case agent.FrameRun, agent.FrameTest:
			if !flights.begin() {
				// Stopping: answered at once rather than started, so the
				// server is not left waiting on a check that will never
				// report.
				_ = writeFrame(sctx, conn, resultFrame(f.ID, http.StatusOK, agent.Response{
					Action: f.Check, OK: false, DateTime: time.Now(), NewStatusID: agent.StatusUnknown,
					Status: "the agent is stopping", Version: version.Version(),
				}))
				continue
			}
			go func(f agent.Frame) {
				defer flights.end()
				code, resp := c.answer(sctx, h, f)
				if err := writeFrame(sctx, conn, resultFrame(f.ID, code, resp)); err != nil {
					c.log.Warn("could not send a result", "check", f.Check, "error", err)
				}
			}(f)
		default:
			// A newer server's frame. Ignored rather than fatal, so a server
			// can grow the protocol without first replacing every agent.
			c.log.Debug("ignored a frame of unknown type", "type", f.Type)
		}
	}
}

// dial opens one connection to target with token, agreeing the protocol.
func dial(ctx context.Context, target, token string) (*websocket.Conn, error) {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("User-Agent", "gryphon-agent/"+version.Version())

	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	conn, resp, err := websocket.Dial(dialCtx, target, &websocket.DialOptions{
		HTTPHeader:   header,
		Subprotocols: []string{agent.Subprotocol},
	})
	if err != nil {
		return nil, dialError(resp, err)
	}
	if conn.Subprotocol() != agent.Subprotocol {
		// At once rather than with a close handshake: a server that did not
		// agree the protocol cannot be relied on to finish one.
		conn.CloseNow()
		return nil, ErrIncompatible
	}
	conn.SetReadLimit(agent.MaxFrameSize)
	return conn, nil
}

// helloFrame is what the agent says about itself on every connection.
func helloFrame(h *handlers) agent.Frame {
	hostname, _ := os.Hostname()
	return agent.Frame{Type: agent.FrameHello, Hello: &agent.Hello{
		Version:  version.Version(),
		Checks:   h.checkNames(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
	}}
}

// Verify connects to Gryphon once with cfg's token, says hello and
// disconnects. It is the check enrolling makes before it saves the token
// anywhere: a token copied short, or replaced since, is said to be wrong
// while the person who pasted it is still looking, rather than discovered in
// a log after the agent has started.
func Verify(ctx context.Context, cfg Config) error {
	cfg = cfg.withDefaults()
	if err := ValidateKey(cfg.Key); err != nil {
		return err
	}
	target, err := ConnectURL(cfg.Server, cfg.AllowInsecureServer)
	if err != nil {
		return err
	}
	conn, err := dial(ctx, target, cfg.Key)
	if err != nil {
		return err
	}
	if err := writeFrame(ctx, conn, helloFrame(newHandlers(cfg, slog.New(slog.DiscardHandler)))); err != nil {
		conn.CloseNow()
		return err
	}
	// The server answers the close at once; its error, if any, changes
	// nothing about the token having been accepted.
	_ = conn.Close(websocket.StatusNormalClosure, "enrolled")
	return nil
}

// answer runs one frame's request. A panic is answered rather than allowed to
// end the agent.
func (c *Connector) answer(ctx context.Context, h *handlers, f agent.Frame) (code int, resp agent.Response) {
	defer func() {
		if rec := recover(); rec != nil {
			c.log.Error("panic answering the server", "check", f.Check, "panic", rec)
			code, resp = http.StatusInternalServerError, agent.Response{
				Action: f.Check, OK: false, Status: "internal error", DateTime: time.Now(),
				Version: version.Version(),
			}
		}
	}()
	if f.Type == agent.FrameTest {
		return http.StatusOK, h.testResponse()
	}
	return h.run(ctx, f.Check, f.Parameters)
}

func resultFrame(id string, code int, resp agent.Response) agent.Frame {
	return agent.Frame{Type: agent.FrameResult, ID: id, Code: code, Response: &resp}
}

func writeFrame(ctx context.Context, conn *websocket.Conn, f agent.Frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, frameWriteTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, data)
}

// keepalive pings the server until the connection ends, and drops a
// connection whose server has stopped answering, so that the read loop
// returns and the agent reconnects rather than waiting on a dead socket.
func keepalive(ctx context.Context, conn *websocket.Conn, log *slog.Logger) {
	ticker := time.NewTicker(agent.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pingCtx, cancel := context.WithTimeout(ctx, agent.KeepaliveInterval)
		err := conn.Ping(pingCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Warn("server stopped answering", "error", err)
			conn.CloseNow()
			return
		}
	}
}

// dialError says why a dial failed, telling a refusal -- which no number of
// retries will fix -- from the server being unreachable, which time may.
func dialError(resp *http.Response, err error) error {
	if resp == nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if why := responseText(resp); why != "" {
			return fmt.Errorf("%w: %s", ErrTokenRefused, why)
		}
		return ErrTokenRefused
	case http.StatusUpgradeRequired:
		return ErrIncompatible
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		if secs, convErr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); convErr == nil && secs > 0 {
			return &busyError{wait: time.Duration(secs) * time.Second, why: responseText(resp)}
		}
	}
	return fmt.Errorf("server answered %s: %w", resp.Status, err)
}

// busyError is a server that turned the agent away for now and said when to
// try again: too many agents connecting at once, or an instance shutting
// down.
type busyError struct {
	wait time.Duration
	why  string
}

func (e *busyError) Error() string {
	if e.why == "" {
		return fmt.Sprintf("the server is busy; try again in %s", e.wait)
	}
	return fmt.Sprintf("the server is busy (%s); try again in %s", e.why, e.wait)
}

// responseText is the start of a refusal's body, which the server uses to
// say why, as one line.
func responseText(resp *http.Response) string {
	if resp.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return strings.Join(strings.Fields(string(b)), " ")
}

// inFlight counts the checks a connection is running, so that stopping can
// wait for them to answer and refuse new ones meanwhile.
type inFlight struct {
	mu      sync.Mutex
	n       int
	closing bool
	idle    chan struct{}
}

// begin counts a check in, or reports false once the connection is closing.
func (f *inFlight) begin() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing {
		return false
	}
	f.n++
	return true
}

func (f *inFlight) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.closing && f.n == 0 {
		close(f.idle)
	}
}

// drain stops new checks being counted in and returns a channel closed once
// the ones running have finished.
func (f *inFlight) drain() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closing {
		f.closing = true
		f.idle = make(chan struct{})
		if f.n == 0 {
			close(f.idle)
		}
	}
	return f.idle
}
