package clientagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

const connectorTestToken = "connector-test-token-0123456789abcdefghijk"

// fakeServer stands in for Gryphon's end of the connection: it accepts an
// agent with the right token and hands each connection to the test.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server
	// conns receives every connection accepted.
	conns chan *fakeConn
	// attempts counts connection attempts, accepted or not.
	attempts atomic.Int32
	// refuse, when set, answers every attempt with this status instead.
	refuse atomic.Int32
	// noProtocol accepts without agreeing the subprotocol.
	noProtocol atomic.Bool
	// busy, when set, answers 503 with Retry-After of that many seconds.
	busy atomic.Int32
}

type fakeConn struct {
	t      *testing.T
	c      *websocket.Conn
	hello  agent.Hello
	header http.Header
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, conns: make(chan *fakeConn, 16)}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.attempts.Add(1)
		if r.URL.Path != agent.ConnectPath {
			http.NotFound(w, r)
			return
		}
		if secs := fs.busy.Load(); secs != 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(secs)))
			http.Error(w, "too many agents connecting at once", http.StatusServiceUnavailable)
			return
		}
		if code := int(fs.refuse.Load()); code != 0 {
			http.Error(w, "token not recognised", code)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+connectorTestToken {
			http.Error(w, "wrong token", http.StatusUnauthorized)
			return
		}
		opts := &websocket.AcceptOptions{Subprotocols: []string{agent.Subprotocol}}
		if fs.noProtocol.Load() {
			opts = nil
		}
		c, err := websocket.Accept(w, r, opts)
		if err != nil {
			return
		}
		c.SetReadLimit(agent.MaxFrameSize)
		fc := &fakeConn{t: t, c: c, header: r.Header.Clone()}
		if fs.noProtocol.Load() {
			fs.conns <- fc
			return
		}
		f := fc.next()
		if f.Type != agent.FrameHello || f.Hello == nil {
			t.Errorf("first frame = %+v; want a hello", f)
			return
		}
		fc.hello = *f.Hello
		fs.conns <- fc
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

// accept waits for the next connection.
func (fs *fakeServer) accept() *fakeConn {
	fs.t.Helper()
	select {
	case fc := <-fs.conns:
		fs.t.Cleanup(func() { fc.c.CloseNow() })
		return fc
	case <-time.After(5 * time.Second):
		fs.t.Fatal("the agent did not connect")
		return nil
	}
}

// send writes a frame to the agent.
func (fc *fakeConn) send(f agent.Frame) {
	fc.t.Helper()
	data, _ := json.Marshal(f)
	if err := fc.c.Write(context.Background(), websocket.MessageText, data); err != nil {
		fc.t.Fatalf("send: %v", err)
	}
}

// next reads the agent's next frame.
func (fc *fakeConn) next() agent.Frame {
	fc.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := fc.c.Read(ctx)
	if err != nil {
		fc.t.Fatalf("read: %v", err)
	}
	var f agent.Frame
	if err := json.Unmarshal(data, &f); err != nil {
		fc.t.Fatalf("frame %q: %v", data, err)
	}
	return f
}

// results reads n results, by id.
func (fc *fakeConn) results(n int) map[string]agent.Frame {
	fc.t.Helper()
	out := map[string]agent.Frame{}
	for range n {
		f := fc.next()
		if f.Type != agent.FrameResult || f.Response == nil {
			fc.t.Fatalf("frame = %+v; want a result", f)
		}
		out[f.ID] = f
	}
	return out
}

// fastPacing shrinks every wait the Connector makes, for the test.
func fastPacing(t *testing.T) {
	t.Helper()
	oldMin, oldMax, oldRefused, oldAway := minBackoff, maxBackoff, refusedBackoff, goingAwayJitter
	minBackoff, maxBackoff, refusedBackoff, goingAwayJitter = 10*time.Millisecond, 50*time.Millisecond, 300*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		minBackoff, maxBackoff, refusedBackoff, goingAwayJitter = oldMin, oldMax, oldRefused, oldAway
	})
}

// startConnector starts an agent against fs and stops it when the test ends.
func startConnector(t *testing.T, fs *fakeServer, cfg Config) *Connector {
	t.Helper()
	cfg.Server = fs.srv.URL
	cfg.AllowInsecureServer = true
	if cfg.Key == "" {
		cfg.Key = connectorTestToken
	}
	c := NewConnector(cfg, nil, nil)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	return c
}

// waitFor polls cond until it holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConnectURL(t *testing.T) {
	tests := []struct {
		server   string
		insecure bool
		want     string
		wantErr  string
	}{
		{"", false, "wss://gryphon.gocode.ca/agent/v1/connect", ""},
		{"https://gryphon.example.com", false, "wss://gryphon.example.com/agent/v1/connect", ""},
		{" https://gryphon.example.com/ ", false, "wss://gryphon.example.com/agent/v1/connect", ""},
		{"https://example.com:8443/gryphon/", false, "wss://example.com:8443/gryphon/agent/v1/connect", ""},
		{"http://localhost:4001", true, "ws://localhost:4001/agent/v1/connect", ""},
		{"http://localhost:4001", false, "", "GWC_ALLOW_INSECURE_SERVER"},
		{"ftp://example.com", true, "", "https://"},
		{"gryphon.example.com", false, "", "https://"},
		{"https://", false, "", "no host"},
		{"https://user:pw@example.com", false, "", "plain address"},
		{"https://example.com?x=1", false, "", "plain address"},
	}
	for _, tt := range tests {
		got, err := ConnectURL(tt.server, tt.insecure)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ConnectURL(%q, %v) error = %v; want one mentioning %q", tt.server, tt.insecure, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ConnectURL(%q, %v) = %q, %v; want %q", tt.server, tt.insecure, got, err, tt.want)
		}
	}
}

func TestConnectorStartRefusesWhatCanNeverConnect(t *testing.T) {
	if err := NewConnector(Config{}, nil, nil).Start(); !errors.Is(err, ErrNoKey) {
		t.Errorf("Start with no token = %v; want ErrNoKey", err)
	}
	c := NewConnector(Config{Key: connectorTestToken, Server: "http://gryphon.example.com"}, nil, nil)
	if err := c.Start(); err == nil {
		t.Error("Start with an http:// server and no permission for it succeeded")
	}
	if c.Running() {
		t.Error("a Connector that refused to start says it is running")
	}
}

// The agent connects as soon as it starts, presents its token, and says who
// it is before anything else.
func TestConnectorConnectsAtOnceAndSaysHello(t *testing.T) {
	fs := newFakeServer(t)
	c := startConnector(t, fs, Config{})
	fc := fs.accept()

	if fc.hello.Version == "" || fc.hello.OS == "" || fc.hello.Arch == "" {
		t.Errorf("hello = %+v; want the build, OS and architecture", fc.hello)
	}
	if !slices.Contains(fc.hello.Checks, "memory") || !slices.Contains(fc.hello.Checks, "disk-space") {
		t.Errorf("hello checks = %v; want the checks this agent runs", fc.hello.Checks)
	}
	if ua := fc.header.Get("User-Agent"); !strings.HasPrefix(ua, "gryphon-agent/") {
		t.Errorf("User-Agent = %q", ua)
	}
	waitFor(t, "connected", func() bool { return c.Status().State == Connected })
	if c.Status().Server != fs.srv.URL {
		t.Errorf("status server = %q; want %q", c.Status().Server, fs.srv.URL)
	}
}

// Runs and tests are answered, each with its own id, and a check this build
// does not know is a 404 the server can read.
func TestConnectorAnswersByID(t *testing.T) {
	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()

	fc.send(agent.Frame{Type: agent.FrameRun, ID: "a", Check: "memory"})
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "b", Check: "no-such-check"})
	fc.send(agent.Frame{Type: agent.FrameTest, ID: "c"})
	got := fc.results(3)

	if a := got["a"]; a.Code != http.StatusOK || a.Response.Measurement == nil || a.Response.Version == "" {
		t.Errorf("memory = %d %+v; want a reading and the build", a.Code, a.Response)
	}
	if b := got["b"]; b.Code != http.StatusNotFound || b.Response.Status != agent.UnknownCheckStatus || len(b.Response.Checks) == 0 {
		t.Errorf("unknown check = %d %+v; want 404, %q and the check list", b.Code, b.Response, agent.UnknownCheckStatus)
	}
	if c := got["c"]; c.Code != http.StatusOK || !c.Response.OK || len(c.Response.Checks) == 0 {
		t.Errorf("test = %d %+v; want OK and the check list", c.Code, c.Response)
	}
}

// Parameters reach the check as the server sent them.
func TestConnectorPassesParameters(t *testing.T) {
	var seen atomic.Value
	checkFuncs["echo-test-check"] = func(_ context.Context, p string) result {
		seen.Store(p)
		return result{statusID: agent.StatusHealthy, msg: "ok"}
	}
	t.Cleanup(func() { delete(checkFuncs, "echo-test-check") })

	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "p", Check: "echo-test-check", Parameters: "host=db&port=5432"})
	if r := fc.results(1)["p"]; r.Response.NewStatusID != agent.StatusHealthy {
		t.Fatalf("result = %+v", r.Response)
	}
	if got, _ := seen.Load().(string); got != "host=db&port=5432" {
		t.Errorf("check saw parameters %q", got)
	}
}

// A dropped connection is reconnected, without anyone asking.
func TestConnectorReconnectsAfterADrop(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	c := startConnector(t, fs, Config{})
	fs.accept().c.CloseNow()

	fc := fs.accept()
	fc.send(agent.Frame{Type: agent.FrameTest, ID: "again"})
	if r := fc.results(1)["again"]; !r.Response.OK {
		t.Errorf("after reconnecting, test = %+v", r.Response)
	}
	waitFor(t, "connected", func() bool { return c.Status().State == Connected })
}

// A server that is restarting says so, and the agent goes straight back.
func TestConnectorReconnectsQuicklyAfterGoingAway(t *testing.T) {
	fastPacing(t)
	maxBackoff = time.Hour // only the going-away path can bring it back in time
	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fs.accept().c.Close(websocket.StatusGoingAway, "server restarting")
	fs.accept()
}

// The server being unreachable is retried, with the wait growing.
func TestConnectorRetriesAnUnreachableServer(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	fs.refuse.Store(http.StatusBadGateway)
	c := startConnector(t, fs, Config{})

	waitFor(t, "several attempts", func() bool { return fs.attempts.Load() >= 3 })
	if st := c.Status(); st.State != Retrying && st.State != Connecting {
		t.Errorf("status = %v (%v); want retrying", st.State, st.Err)
	}

	fs.refuse.Store(0)
	fs.accept()
}

// A server that is busy says when to come back, and the agent waits that long.
func TestConnectorWaitsAsLongAsABusyServerAsks(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	fs.busy.Store(1) // Retry-After: 1
	c := startConnector(t, fs, Config{})

	waitFor(t, "turned away", func() bool { return c.Status().Err != nil })
	st := c.Status()
	if st.State != Retrying || !strings.Contains(st.Err.Error(), "busy") {
		t.Errorf("status = %v %v; want retrying, busy", st.State, st.Err)
	}
	if wait := time.Until(st.RetryAt); wait < 900*time.Millisecond {
		t.Errorf("next attempt in %s; the server asked for 1s", wait)
	}
	time.Sleep(500 * time.Millisecond)
	if n := fs.attempts.Load(); n != 1 {
		t.Errorf("%d attempts before the server's time was up; want 1", n)
	}

	fs.busy.Store(0)
	fs.accept()
}

// A refused token is retried slowly, and the status says why.
func TestConnectorBacksOffWhenTheTokenIsRefused(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	fs.refuse.Store(http.StatusUnauthorized)
	c := startConnector(t, fs, Config{})

	waitFor(t, "refused", func() bool { return c.Status().State == Refused })
	st := c.Status()
	if !errors.Is(st.Err, ErrTokenRefused) || !strings.Contains(st.Err.Error(), "token not recognised") {
		t.Errorf("status error = %v; want ErrTokenRefused with the server's reason", st.Err)
	}
	if wait := time.Until(st.RetryAt); wait < refusedBackoff/2 {
		t.Errorf("next attempt in %s; want about %s", wait, refusedBackoff)
	}
	time.Sleep(refusedBackoff / 2)
	if n := fs.attempts.Load(); n != 1 {
		t.Errorf("%d attempts within half the refusal backoff; want 1", n)
	}

	fs.refuse.Store(0)
	fs.accept()
}

// A token revoked on an open connection is treated as a refusal.
func TestConnectorTreatsRevocationAsARefusal(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	c := startConnector(t, fs, Config{})
	fs.accept().c.Close(agent.CloseRevoked, "token replaced")

	waitFor(t, "refused", func() bool { return c.Status().State == Refused })
	if err := c.Status().Err; !errors.Is(err, ErrTokenRefused) {
		t.Errorf("status error = %v; want ErrTokenRefused", err)
	}
}

// A server that does not speak this protocol is not talked to.
func TestConnectorRefusesAServerWithoutTheProtocol(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	fs.noProtocol.Store(true)
	c := startConnector(t, fs, Config{})

	waitFor(t, "refused", func() bool { return c.Status().State == Refused })
	if err := c.Status().Err; !errors.Is(err, ErrIncompatible) {
		t.Errorf("status error = %v; want ErrIncompatible", err)
	}
}

// Past the cap the agent says it is busy rather than starting one more.
func TestConnectorCapsChecksInFlight(t *testing.T) {
	release := make(chan struct{})
	checkFuncs["slow-test-check"] = func(ctx context.Context, _ string) result {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return result{statusID: agent.StatusHealthy, msg: "done"}
	}
	t.Cleanup(func() { delete(checkFuncs, "slow-test-check") })

	fs := newFakeServer(t)
	startConnector(t, fs, Config{MaxConcurrent: 1})
	fc := fs.accept()

	fc.send(agent.Frame{Type: agent.FrameRun, ID: "slow", Check: "slow-test-check"})
	time.Sleep(100 * time.Millisecond) // let it take the slot
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "second", Check: "memory"})
	busy := fc.results(1)["second"]
	if busy.Response == nil || busy.Response.NewStatusID != agent.StatusUnknown || !strings.Contains(busy.Response.Status, "busy") {
		t.Fatalf("second check while the cap is full = %+v; want unknown, busy", busy)
	}

	close(release)
	if r := fc.results(1)["slow"]; r.Response.NewStatusID != agent.StatusHealthy {
		t.Errorf("slow check = %+v", r.Response)
	}
}

// A check past its deadline is answered unknown, and the connection lives on.
func TestConnectorAnswersAStuckCheckAtItsDeadline(t *testing.T) {
	old := checkDeadline
	checkDeadline = 50 * time.Millisecond
	stuck := make(chan struct{})
	checkFuncs["stuck"] = func(context.Context, string) result {
		<-stuck // ignores its context, like a disk on a hung mount
		return result{}
	}
	t.Cleanup(func() { checkDeadline = old; close(stuck); delete(checkFuncs, "stuck") })

	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "s", Check: "stuck"})
	r := fc.results(1)["s"]
	if r.Response.NewStatusID != agent.StatusUnknown || !strings.Contains(r.Response.Status, "did not finish") {
		t.Errorf("stuck check = %+v; want unknown, did not finish", r.Response)
	}
	fc.send(agent.Frame{Type: agent.FrameTest, ID: "t"})
	if r := fc.results(1)["t"]; !r.Response.OK {
		t.Errorf("after a stuck check, test = %+v", r.Response)
	}
}

// A check that panics is answered, and the agent keeps running.
func TestConnectorSurvivesACheckThatPanics(t *testing.T) {
	checkFuncs["panics"] = func(context.Context, string) result { panic("boom") }
	t.Cleanup(func() { delete(checkFuncs, "panics") })

	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "p", Check: "panics"})
	r := fc.results(1)["p"]
	if r.Response.NewStatusID != agent.StatusUnknown || !strings.Contains(r.Response.Status, "failed unexpectedly") {
		t.Errorf("panicking check = %+v; want unknown", r.Response)
	}
	fc.send(agent.Frame{Type: agent.FrameTest, ID: "t"})
	if r := fc.results(1)["t"]; !r.Response.OK {
		t.Errorf("after a panic, test = %+v", r.Response)
	}
}

// Frames the agent does not understand are passed over, not fatal: a newer
// server can grow the protocol.
func TestConnectorIgnoresFramesItDoesNotKnow(t *testing.T) {
	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()

	fc.send(agent.Frame{Type: "from-the-future", ID: "x"})
	if err := fc.c.Write(context.Background(), websocket.MessageText, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := fc.c.Write(context.Background(), websocket.MessageBinary, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	fc.send(agent.Frame{Type: agent.FrameTest, ID: "t"})
	if r := fc.results(1)["t"]; !r.Response.OK {
		t.Errorf("test after unknown frames = %+v", r.Response)
	}
}

// A frame past the size limit ends the connection, and the agent comes back.
func TestConnectorDropsAnOversizedFrame(t *testing.T) {
	fastPacing(t)
	fs := newFakeServer(t)
	startConnector(t, fs, Config{})
	fc := fs.accept()

	huge := agent.Frame{Type: agent.FrameRun, ID: "big", Check: "memory", Parameters: strings.Repeat("x", agent.MaxFrameSize)}
	data, _ := json.Marshal(huge)
	_ = fc.c.Write(context.Background(), websocket.MessageText, data)

	fs.accept()
}

// Stopping lets a check in progress answer, refuses new ones meanwhile, and
// then closes the connection normally.
func TestConnectorStopsAfterChecksInProgressAnswer(t *testing.T) {
	release := make(chan struct{})
	checkFuncs["slow-test-check"] = func(ctx context.Context, _ string) result {
		<-release
		return result{statusID: agent.StatusHealthy, msg: "done"}
	}
	t.Cleanup(func() { delete(checkFuncs, "slow-test-check") })

	fs := newFakeServer(t)
	c := startConnector(t, fs, Config{})
	fc := fs.accept()
	fc.send(agent.Frame{Type: agent.FrameRun, ID: "slow", Check: "slow-test-check"})
	time.Sleep(50 * time.Millisecond)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = c.Stop(context.Background())
	}()
	time.Sleep(50 * time.Millisecond)

	fc.send(agent.Frame{Type: agent.FrameRun, ID: "late", Check: "memory"})
	if r := fc.results(1)["late"]; !strings.Contains(r.Response.Status, "stopping") {
		t.Errorf("a check sent while stopping = %+v; want it refused", r.Response)
	}

	close(release)
	if r := fc.results(1)["slow"]; r.Response.NewStatusID != agent.StatusHealthy {
		t.Errorf("the check in progress = %+v; want its answer", r.Response)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := fc.c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Errorf("connection ended with %v; want a normal closure", err)
	}
	<-stopped
	if c.Running() || c.Status().State != Stopped {
		t.Errorf("after Stop: running %v, state %v", c.Running(), c.Status().State)
	}
}

// The on/off switch: stopped, the agent can be started again, and connects.
func TestConnectorStartsAgainAfterStop(t *testing.T) {
	fs := newFakeServer(t)
	c := startConnector(t, fs, Config{})
	fs.accept().c.CloseRead(context.Background()) // answers the agent's close, as the server does

	if err := c.Start(); !errors.Is(err, ErrRunning) {
		t.Errorf("second Start = %v; want ErrRunning", err)
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(context.Background()); err != nil {
		t.Errorf("stopping a stopped agent = %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	fs.accept()
}

// Every change of state is reported, in order, for a menu's status line.
func TestConnectorReportsItsStatus(t *testing.T) {
	fs := newFakeServer(t)
	states := make(chan ConnState, 16)
	c := NewConnector(Config{Key: connectorTestToken, Server: fs.srv.URL, AllowInsecureServer: true}, nil,
		func(st ConnStatus) { states <- st.State })
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	fs.accept().c.CloseRead(context.Background())
	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(states)
	var got []ConnState
	for s := range states {
		got = append(got, s)
	}
	want := []ConnState{Connecting, Connected, Stopped}
	if !slices.Equal(got, want) {
		t.Errorf("states = %v; want %v", got, want)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	for n := range 64 {
		bound := maxBackoff
		if n < 6 {
			bound = minBackoff << n
		}
		for range 50 {
			if d := backoff(n); d < 0 || d > bound {
				t.Fatalf("backoff(%d) = %s; want within [0, %s]", n, d, bound)
			}
		}
	}
}

// Verify says hello once with the token and goes, so enrolling learns at once
// whether the token is good.
func TestVerify(t *testing.T) {
	fs := newFakeServer(t)
	cfg := Config{Key: connectorTestToken, Server: fs.srv.URL, AllowInsecureServer: true}
	if err := Verify(context.Background(), cfg); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	fc := fs.accept()
	if fc.hello.Version == "" {
		t.Errorf("hello = %+v", fc.hello)
	}

	fs.refuse.Store(http.StatusUnauthorized)
	if err := Verify(context.Background(), cfg); !errors.Is(err, ErrTokenRefused) {
		t.Errorf("a refused token: %v; want ErrTokenRefused", err)
	}
	if err := Verify(context.Background(), Config{Key: "short", Server: fs.srv.URL, AllowInsecureServer: true}); err == nil {
		t.Error("a malformed token was sent")
	}
}
