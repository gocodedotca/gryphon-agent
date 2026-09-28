package clientagent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// testKey is a well-formed access key for the tests.
const testKey = "test-key-0123456789abcdefghijklmnopqrstuvwxyz"

func TestValidateKey(t *testing.T) {
	good, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKey(good); err != nil {
		t.Errorf("a generated key was refused: %v", err)
	}
	if len(good) < MinKeyLength {
		t.Errorf("a generated key is %d characters, shorter than the minimum", len(good))
	}
	other, _ := GenerateKey()
	if other == good {
		t.Error("two generated keys are the same")
	}

	for name, key := range map[string]string{
		"empty":       "",
		"short":       "hunter2",
		"with spaces": "this key has spaces in it and is long enough",
		"non-ascii":   "clé-0123456789abcdefghijklmnopqrstuvwxyz",
		"too long":    strings.Repeat("k", 257),
	} {
		if err := ValidateKey(key); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
}

func TestDefaults(t *testing.T) {
	if got := (Config{}).withDefaults().Addr; got != DefaultAddr {
		t.Errorf("addr = %q, want the default", got)
	}
	if got := (Config{Addr: "7001"}).withDefaults().Addr; got != ":7001" {
		t.Errorf("bare port became %q", got)
	}
	if got := (Config{Addr: "127.0.0.1:7001"}).withDefaults().Addr; got != "127.0.0.1:7001" {
		t.Errorf("host:port became %q", got)
	}
	// A key read from a secret file carries its trailing newline.
	if got := (Config{Key: testKey + "\n"}).withDefaults().Key; got != testKey {
		t.Errorf("key = %q, want it trimmed", got)
	}
}

// There is no running without a key: the agent would otherwise answer the
// database checks for anyone who can reach the port.
func TestStartRefusesWithoutAKey(t *testing.T) {
	for _, key := range []string{"", "short"} {
		ag := New(Config{Addr: "127.0.0.1:0", Key: key}, nil)
		if err := ag.Start(); err == nil {
			_ = ag.Stop(context.Background())
			t.Errorf("started with key %q", key)
		}
		if ag.Running() {
			t.Errorf("claims to be running with key %q", key)
		}
	}
}

// The on/off switch: an agent starts, answers, stops, and the port is free
// again at once so it can start again.
func TestAgentStartsAndStops(t *testing.T) {
	ag := New(Config{Addr: "127.0.0.1:0", Key: testKey}, nil)
	if ag.Running() {
		t.Fatal("running before Start")
	}
	if err := ag.Start(); err != nil {
		t.Fatal(err)
	}
	if err := ag.Start(); err != ErrRunning {
		t.Errorf("second Start = %v, want ErrRunning", err)
	}
	addr := ag.Addr()
	if addr == nil {
		t.Fatal("no address while running")
	}

	req, _ := http.NewRequest("GET", "http://"+addr.String()+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ag.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if ag.Running() {
		t.Error("running after Stop")
	}
	if _, err := net.DialTimeout("tcp", addr.String(), 200*time.Millisecond); err == nil {
		t.Error("port still accepting connections after Stop")
	}
	if err := ag.Stop(ctx); err != nil {
		t.Errorf("Stop when stopped = %v, want nil", err)
	}

	// Start again on the same port: nothing from the first run is in the way.
	ag2 := New(Config{Addr: addr.String(), Key: testKey}, nil)
	if err := ag2.Start(); err != nil {
		t.Fatalf("restart on the same port: %v", err)
	}
	_ = ag2.Stop(ctx)
}

// A port in use is Start's error, not a log line -- the menu bar app shows it.
func TestAgentStartReportsPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ag := New(Config{Addr: ln.Addr().String(), Key: testKey}, nil)
	if err := ag.Start(); err == nil {
		_ = ag.Stop(context.Background())
		t.Fatal("Start on a busy port returned nil")
	}
	if ag.Running() {
		t.Error("claims to be running after a failed Start")
	}
}

type testHandler struct{ http.Handler }

func (h testHandler) routes() http.Handler { return h.Handler }

// testApp is the agent's handler with testKey as its access key.
func testApp(t *testing.T) testHandler {
	t.Helper()
	return testHandler{Handler(Config{Key: testKey}, slog.New(slog.NewTextHandler(os.Stderr, nil)))}
}

// The server's connectivity test is a GET with no body; the old client tried
// to JSON-parse the empty body and answered "Error parsing json".
func TestTestEndpointAnswersBodylessGet(t *testing.T) {
	app := testApp(t)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp agent.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Action != "test" {
		t.Errorf("resp = %+v, want ok test", resp)
	}
}

// Every request needs the key, from any address. Loopback in particular gets no
// pass: behind a reverse proxy on the same machine, every request arrives from
// loopback.
func TestAccessKeyEnforced(t *testing.T) {
	app := testApp(t)

	for name, header := range map[string]string{
		"no header":           "",
		"the wrong key":       "Bearer wrong-key-0123456789abcdefghijklmnopqrstuvwxyz",
		"the key as a prefix": "Bearer " + testKey + "x",
		"a truncated key":     "Bearer " + testKey[:len(testKey)-1],
		"another scheme":      "Basic " + testKey,
		"no scheme":           testKey,
		"an empty bearer":     "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/test", "/memory", "/postgres"} {
				method := "POST"
				if path == "/test" {
					method = "GET"
				}
				req := httptest.NewRequest(method, path, nil)
				req.RemoteAddr = "127.0.0.1:9999"
				if header != "" {
					req.Header.Set("Authorization", header)
				}
				rec := httptest.NewRecorder()
				app.routes().ServeHTTP(rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("%s: status = %d, want 401", path, rec.Code)
				}
				if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="gryphon-agent"`) {
					t.Errorf("%s: WWW-Authenticate = %q, want the agent's realm", path, got)
				}
				var resp agent.Response
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if resp.OK || resp.Measurement != nil {
					t.Errorf("%s: a refused request reported something: %+v", path, resp)
				}
			}
		})
	}

	t.Run("the scheme is case-insensitive", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "bearer "+testKey)
		rec := httptest.NewRecorder()
		app.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

// A handler embedded with no key refuses everything, rather than matching an
// empty key against an empty header.
func TestHandlerWithoutAKeyRefusesEverything(t *testing.T) {
	h := Handler(Config{}, nil)
	for _, header := range []string{"", "Bearer ", "Bearer x"} {
		req := httptest.NewRequest("GET", "/test", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, rec.Code)
		}
	}
}

// A memory check exercised end to end through the handler: the old client's
// integer division reported 0% used forever.
func TestMemoryCheckReportsRealUsage(t *testing.T) {
	app := testApp(t)

	req := httptest.NewRequest("POST", "/memory", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp agent.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Measurement == nil {
		t.Fatalf("no reading reported: %+v", resp)
	}
	// A running machine uses more than 0% of its memory.
	if *resp.Measurement <= 0 {
		t.Errorf("implausible memory reading: %v", *resp.Measurement)
	}
	if resp.Status == "" || resp.Status == "memory: 0.0% used" {
		t.Errorf("implausible memory report: %q", resp.Status)
	}
}

// The sensor protocol: the four system checks report a number and no opinion
// about it. The thresholds live on the server, so an agent that also shipped a
// verdict would be a second place for alerting policy to live.
func TestSystemChecksReportAMeasurement(t *testing.T) {
	app := testApp(t)

	for _, action := range []string{"disk-space", "memory", "cpu", "load"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/"+action, nil)
			req.Header.Set("Authorization", "Bearer "+testKey)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			if rec.Code != 200 {
				t.Fatalf("status = %d", rec.Code)
			}
			var resp agent.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}

			if resp.Measurement == nil {
				t.Fatalf("no measurement reported: %+v", resp)
			}
			if *resp.Measurement < 0 {
				t.Errorf("measurement = %v, which is not a quantity", *resp.Measurement)
			}
			// And no verdict: zero is "the agent has no opinion", which is the
			// only honest thing it can say without thresholds.
			if resp.NewStatusID != 0 {
				t.Errorf("the agent shipped a verdict of %d alongside its reading; grading is the server's job",
					resp.NewStatusID)
			}
		})
	}
}

// The database checks are pass/fail and must not start claiming to measure
// something -- the server would then grade a connection failure against a disk
// threshold.
func TestDatabaseChecksReportNoMeasurement(t *testing.T) {
	app := testApp(t)

	for _, action := range []string{"postgres", "mariadb", "redis"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/"+action, nil)
			req.Header.Set("Authorization", "Bearer "+testKey)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			var resp agent.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Measurement != nil {
				t.Errorf("%s reported a measurement of %v; it has nothing to measure",
					action, *resp.Measurement)
			}
		})
	}
}

// Percentages are percentages: a check reporting 0.42 for "42% used" would be
// graded against a threshold of 75 and never fire.
func TestPercentageChecksReportPercentages(t *testing.T) {
	app := testApp(t)

	for _, action := range []string{"disk-space", "memory", "cpu"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/"+action, nil)
			req.Header.Set("Authorization", "Bearer "+testKey)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			var resp agent.Response
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if resp.Measurement == nil {
				t.Fatal("no measurement")
			}
			if *resp.Measurement > 100 {
				t.Errorf("%s reported %v, which is not a percentage", action, *resp.Measurement)
			}
		})
	}
}

// postCheck runs one check through the handler with the given parameters.
func postCheck(t *testing.T, action, parameters string) agent.Response {
	t.Helper()
	body, _ := json.Marshal(agent.Request{Parameters: parameters})
	req := httptest.NewRequest("POST", "/"+action, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	testApp(t).routes().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("%s: status = %d", action, rec.Code)
	}
	var resp agent.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func urlParams(values map[string]string) string {
	v := url.Values{}
	for k, s := range values {
		v.Set(k, s)
	}
	return v.Encode()
}

// The network checks are pass/fail like the database checks, and time what
// they reach.
func TestHTTPCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	t.Run("a 2xx is healthy and timed", func(t *testing.T) {
		resp := postCheck(t, "http", urlParams(map[string]string{agent.ParamURL: srv.URL + "/up"}))
		if resp.NewStatusID != agent.StatusHealthy {
			t.Fatalf("status = %d (%q), want healthy", resp.NewStatusID, resp.Status)
		}
		if resp.RTT <= 0 {
			t.Errorf("rtt = %s, want the time the service took", resp.RTT)
		}
		if resp.Measurement != nil {
			t.Error("a network check reported a measurement; it would be graded against a threshold")
		}
	})

	t.Run("anything else is a problem", func(t *testing.T) {
		resp := postCheck(t, "http", urlParams(map[string]string{agent.ParamURL: srv.URL + "/down"}))
		if resp.NewStatusID != agent.StatusProblem {
			t.Errorf("status = %d (%q), want problem", resp.NewStatusID, resp.Status)
		}
	})

	t.Run("the https check will not fetch http", func(t *testing.T) {
		resp := postCheck(t, "https", urlParams(map[string]string{agent.ParamURL: srv.URL}))
		if resp.NewStatusID != agent.StatusUnknown {
			t.Errorf("status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
		}
	})

	t.Run("no URL is unknown", func(t *testing.T) {
		resp := postCheck(t, "http", "")
		if resp.NewStatusID != agent.StatusUnknown {
			t.Errorf("status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
		}
	})
}

// A self-signed certificate fails unless the check has said not to verify it.
func TestHTTPSCheckVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	resp := postCheck(t, "https", urlParams(map[string]string{agent.ParamURL: srv.URL}))
	if resp.NewStatusID != agent.StatusProblem {
		t.Errorf("verified: status = %d (%q), want problem", resp.NewStatusID, resp.Status)
	}

	resp = postCheck(t, "https", urlParams(map[string]string{agent.ParamURL: srv.URL, agent.ParamVerify: "false"}))
	if resp.NewStatusID != agent.StatusHealthy {
		t.Errorf("unverified: status = %d (%q), want healthy", resp.NewStatusID, resp.Status)
	}
}

func TestPingCheck(t *testing.T) {
	resp := postCheck(t, "ping", urlParams(map[string]string{agent.ParamHost: "127.0.0.1"}))
	if resp.NewStatusID != agent.StatusHealthy && resp.NewStatusID != agent.StatusUnknown {
		t.Errorf("loopback: status = %d (%q), want healthy or unknown", resp.NewStatusID, resp.Status)
	}

	resp = postCheck(t, "ping", "")
	if resp.NewStatusID != agent.StatusUnknown {
		t.Errorf("no host: status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
	}
}

// A check that runs past the deadline is answered for, as unknown, rather than
// left to outlast the write timeout and look like an agent that is down.
func TestACheckPastItsDeadlineIsAnsweredUnknown(t *testing.T) {
	oldDeadline := checkDeadline
	checkDeadline = 50 * time.Millisecond
	release := make(chan struct{})
	checkFuncs["stuck"] = func(context.Context, string) result {
		<-release // ignores its context, like a hung syscall
		return result{statusID: agent.StatusHealthy}
	}
	t.Cleanup(func() {
		close(release)
		delete(checkFuncs, "stuck")
		checkDeadline = oldDeadline
	})

	start := time.Now()
	resp := postCheck(t, "stuck", "")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("answered after %s; the deadline is %s", elapsed, checkDeadline)
	}
	if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "did not finish") {
		t.Errorf("got status %d (%q), want unknown saying it did not finish", resp.NewStatusID, resp.Status)
	}
}

// The deadline is only useful if the answer can still be written after it.
func TestWriteTimeoutLeavesRoomAfterTheCheckDeadline(t *testing.T) {
	if writeTimeout < agent.CheckDeadline+3*time.Second {
		t.Errorf("write timeout %s leaves too little after the %s check deadline", writeTimeout, agent.CheckDeadline)
	}
}

// A Redis port that accepts the connection and never replies is a problem
// reported inside the deadline, not a PING held open for ever.
func TestRedisCheckDoesNotHangOnASilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close() // held open, never answered
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := testProbe(t).checkRedis(ctx, ln.Addr().String())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned after %s; it should give up when its context does", elapsed)
	}
	if res.statusID != agent.StatusProblem {
		t.Errorf("got status %d (%q), want problem", res.statusID, res.msg)
	}
}

// The agent's Postgres check without credentials: a connection string naming
// no user is answered by the startup handshake rather than a driver session.
// The handshake itself is tested in pkg/netcheck; this pins the routing and
// the wording.
func TestPostgresCheckWithoutCredentials(t *testing.T) {
	t.Run("nothing answering is cannot reach", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host, port, _ := net.SplitHostPort(l.Addr().String())
		_ = l.Close()

		res := testProbe(t).checkPostgres(context.Background(), "host="+host+" port="+port+" sslmode=disable connect_timeout=5")
		if res.statusID != agent.StatusProblem {
			t.Errorf("status %d, message %q", res.statusID, res.msg)
		}
		if !strings.HasPrefix(res.msg, "cannot reach postgres") {
			t.Errorf("message %q", res.msg)
		}
	})

	t.Run("a running server is accepting connections", func(t *testing.T) {
		probe, err := net.DialTimeout("tcp", "127.0.0.1:5432", 500*time.Millisecond)
		if err != nil {
			t.Skip("no Postgres on 127.0.0.1:5432")
		}
		_ = probe.Close()

		res := testProbe(t).checkPostgres(context.Background(), "host=127.0.0.1 port=5432 sslmode=prefer connect_timeout=5")
		if res.statusID != agent.StatusHealthy {
			t.Fatalf("status %d, message %q", res.statusID, res.msg)
		}
		if res.msg != "postgres is accepting connections" {
			t.Errorf("message %q", res.msg)
		}
		if res.rtt <= 0 {
			t.Error("the round trip was not recorded")
		}
	})
}

// The agent's MariaDB check without credentials, routed like the Postgres one.
func TestMariaDBCheckWithoutCredentials(t *testing.T) {
	t.Run("nothing answering is cannot reach", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()

		res := testProbe(t).checkMariaDB(context.Background(), "tcp("+addr+")/?parseTime=true&tls=false&timeout=5s")
		if res.statusID != agent.StatusProblem || !strings.HasPrefix(res.msg, "cannot reach mariadb") {
			t.Errorf("status %d, message %q", res.statusID, res.msg)
		}
	})

	t.Run("a DSN with a user still signs in", func(t *testing.T) {
		// Nothing listening either way, but the wording is the driver's:
		// this went through the credentialed path.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		res := testProbe(t).checkMariaDB(context.Background(), "watch:p@tcp("+addr+")/app?parseTime=true&tls=false&timeout=5s")
		if res.statusID != agent.StatusProblem || strings.Contains(res.msg, "accepting connections") {
			t.Errorf("status %d, message %q", res.statusID, res.msg)
		}
	})

	t.Run("a running server is accepting connections", func(t *testing.T) {
		probe, err := net.DialTimeout("tcp", "127.0.0.1:3307", 500*time.Millisecond)
		if err != nil {
			t.Skip("no MariaDB on 127.0.0.1:3307")
		}
		_ = probe.Close()
		res := testProbe(t).checkMariaDB(context.Background(), "tcp(127.0.0.1:3307)/?parseTime=true&tls=preferred&timeout=5s")
		if res.statusID != agent.StatusHealthy {
			t.Fatalf("status %d, message %q", res.statusID, res.msg)
		}
		if !strings.HasPrefix(res.msg, "mariadb is accepting connections (") || !strings.Contains(res.msg, "MariaDB") {
			t.Errorf("message %q", res.msg)
		}
	})
}

// The response settings reach the agent's fetch.
func TestHTTPCheckResponseSettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"cluster":"green"}`))
	}))
	defer srv.Close()

	resp := postCheck(t, "http", urlParams(map[string]string{agent.ParamURL: srv.URL, agent.ParamStatus: "401", agent.ParamContains: "green"}))
	if resp.NewStatusID != agent.StatusHealthy {
		t.Errorf("status = %d (%q), want healthy", resp.NewStatusID, resp.Status)
	}
	resp = postCheck(t, "http", urlParams(map[string]string{agent.ParamURL: srv.URL, agent.ParamStatus: "401", agent.ParamContains: "red"}))
	if resp.NewStatusID != agent.StatusProblem {
		t.Errorf("status = %d (%q), want problem", resp.NewStatusID, resp.Status)
	}
	resp = postCheck(t, "http", urlParams(map[string]string{agent.ParamURL: srv.URL, agent.ParamStatus: "bogus"}))
	if resp.NewStatusID != agent.StatusUnknown {
		t.Errorf("status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
	}
}

// The agent's TCP check reaches the loopback, which the server's may not.
func TestTCPCheck(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("+OK POP3 ready\r\n"))
			_ = conn.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())

	resp := postCheck(t, "tcp", urlParams(map[string]string{agent.ParamHost: host, agent.ParamPort: port, agent.ParamExpect: "+OK"}))
	if resp.NewStatusID != agent.StatusHealthy || resp.RTT <= 0 {
		t.Errorf("status = %d (%q), rtt %s; want healthy and timed", resp.NewStatusID, resp.Status, resp.RTT)
	}
	resp = postCheck(t, "tcp", urlParams(map[string]string{agent.ParamHost: host, agent.ParamPort: port, agent.ParamExpect: "220"}))
	if resp.NewStatusID != agent.StatusProblem {
		t.Errorf("status = %d (%q), want problem", resp.NewStatusID, resp.Status)
	}
	resp = postCheck(t, "tcp", urlParams(map[string]string{agent.ParamPort: port}))
	if resp.NewStatusID != agent.StatusUnknown {
		t.Errorf("no host: status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
	}
}
