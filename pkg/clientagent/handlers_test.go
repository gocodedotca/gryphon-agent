package clientagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

const handlerTestKey = "handler-test-key-0123456789abcdefghijklmnop"

func newTestAgent(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	if cfg.Key == "" {
		cfg.Key = handlerTestKey
	}
	srv := httptest.NewServer(checkHandler(cfg, nil))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, method, path, key string) (int, agent.Response, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader("{}"))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out agent.Response
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

// /test says which build this is and what it runs; an unknown check says the
// same, as a 404 the server can read.
func TestTestAndUnknownCheckCarryTheBuild(t *testing.T) {
	srv := newTestAgent(t, Config{})
	code, out, _ := call(t, srv, http.MethodGet, "/test", handlerTestKey)
	if code != http.StatusOK || out.Version == "" || len(out.Checks) == 0 {
		t.Fatalf("/test = %d %+v; want the build and the check list", code, out)
	}
	for _, want := range []string{"memory", "http", "container"} {
		found := false
		for _, c := range out.Checks {
			found = found || c == want
		}
		if !found {
			t.Errorf("check list %v lacks %s", out.Checks, want)
		}
	}
	for _, c := range out.Checks {
		if c == "script" {
			t.Error("script is listed although no scripts directory was configured")
		}
	}

	code, out, _ = call(t, srv, http.MethodPost, "/no-such-check", handlerTestKey)
	if code != http.StatusNotFound || out.Status != agent.UnknownCheckStatus || out.Version == "" || len(out.Checks) == 0 {
		t.Errorf("unknown check = %d %+v; want 404 naming the build and the list", code, out)
	}
}

// Past the cap the agent says it is busy rather than starting one more.
func TestBusyAgentSaysSo(t *testing.T) {
	release := make(chan struct{})
	checkFuncs["slow-test-check"] = func(ctx context.Context, _ string) result {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return result{statusID: agent.StatusHealthy, msg: "done"}
	}
	t.Cleanup(func() { delete(checkFuncs, "slow-test-check"); close(release) })

	srv := newTestAgent(t, Config{MaxConcurrent: 1})
	started := make(chan struct{})
	go func() {
		close(started)
		call(t, srv, http.MethodPost, "/slow-test-check", handlerTestKey)
	}()
	<-started
	time.Sleep(100 * time.Millisecond) // let the first check take the slot

	code, out, _ := call(t, srv, http.MethodPost, "/memory", handlerTestKey)
	if code != http.StatusOK || out.NewStatusID != agent.StatusUnknown || !strings.Contains(out.Status, "busy") {
		t.Errorf("second check while the cap is full = %d %+v; want unknown, busy", code, out)
	}
}

func TestStripFileParams(t *testing.T) {
	cases := map[string]string{
		"host=db user=app password=x sslkey=/root/.ssh/id_rsa sslmode=require passfile=/etc/passwd": "host=db user=app password=x sslmode=require",
		"postgres://app:x@db:5432/app?sslmode=require&sslrootcert=/etc/ssl/key.pem&service=foo":     "postgres://app:x@db:5432/app?sslmode=require",
		"host=db":                      "host=db",
		"postgres://db/app":            "postgres://db/app",
		"host=db SSLCERT=/x SSLKEY=/y": "host=db",
	}
	for in, want := range cases {
		if got := stripFileParams(in); got != want {
			t.Errorf("stripFileParams(%q) = %q, want %q", in, got, want)
		}
	}
}

// The Engine can be reached over TCP, which is how a socket proxy is used.
func TestDockerClientOverTCP(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Version":"27.1.1"}`))
	}))
	defer engine.Close()

	d := newDockerClient("tcp://" + strings.TrimPrefix(engine.URL, "http://"))
	var out struct{ Version string }
	if err := d.get(context.Background(), "/version", nil, &out); err != nil || out.Version != "27.1.1" {
		t.Errorf("get over tcp = %+v, %v", out, err)
	}
}
