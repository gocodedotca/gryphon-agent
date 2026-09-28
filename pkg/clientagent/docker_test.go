package clientagent

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// fakeEngine is enough of the Docker Engine API for the checks: containers
// by name, one stats document each, and a service list with the prefix
// matching the real one does. It listens on a Unix socket, as the Engine
// does, so the client's dialer is exercised and not just its parsing.
type fakeEngine struct {
	containers map[string]map[string]any
	stats      map[string]map[string]any
	services   []map[string]any
	tasks      []map[string]any
	notManager bool
}

func (f *fakeEngine) serve(t *testing.T) string {
	t.Helper()
	// os.MkdirTemp rather than t.TempDir: a Unix socket path is limited to
	// about a hundred characters and the test name is in t.TempDir's.
	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	notFound := func(what string) { reply(404, map[string]string{"message": "No such " + what}) }

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case parts[0] == "containers" && len(parts) == 3:
		c, ok := f.containers[parts[1]]
		if !ok {
			notFound("container: " + parts[1])
			return
		}
		switch parts[2] {
		case "json":
			reply(200, c)
		case "stats":
			reply(200, f.stats[parts[1]])
		default:
			notFound("path")
		}
	case parts[0] == "services":
		if f.notManager {
			reply(503, map[string]string{"message": "This node is not a swarm manager. Use \"docker swarm init\" or \"docker swarm join\" to connect this node to swarm and try again."})
			return
		}
		var filters struct{ Name, Label []string }
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters)
		out := []map[string]any{}
		for _, s := range f.services {
			spec := s["Spec"].(map[string]any)
			name := spec["Name"].(string)
			for _, prefix := range filters.Name {
				if strings.HasPrefix(name, prefix) {
					out = append(out, s)
				}
			}
			// The real filter is an exact match on "key=value".
			labels, _ := spec["Labels"].(map[string]any)
			for _, want := range filters.Label {
				k, v, _ := strings.Cut(want, "=")
				if got, ok := labels[k]; ok && got == v {
					out = append(out, s)
				}
			}
		}
		reply(200, out)
	case parts[0] == "tasks":
		reply(200, f.tasks)
	default:
		notFound("path")
	}
}

func running(status string, health map[string]any) map[string]any {
	st := map[string]any{"Status": status, "Running": status == "running" || status == "paused" || status == "restarting",
		"Paused": status == "paused", "Restarting": status == "restarting", "StartedAt": "2026-09-16T10:00:00Z"}
	if health != nil {
		st["Health"] = health
	}
	return map[string]any{"Id": "abc", "Name": "/x", "State": st, "HostConfig": map[string]any{}}
}

func service(name string, running, desired int, mode string, update map[string]any) map[string]any {
	m := map[string]any{"Replicated": map[string]any{"Replicas": desired}}
	if mode == "global" {
		m = map[string]any{"Global": map[string]any{}}
	}
	spec := map[string]any{"Name": name, "Mode": m}
	// A service named stack_service carries the stack label, as one
	// deployed by docker stack deploy does.
	if stack, _, ok := strings.Cut(name, "_"); ok {
		spec["Labels"] = map[string]any{"com.docker.stack.namespace": stack}
	}
	s := map[string]any{
		"ID":            "svc-" + name,
		"Spec":          spec,
		"ServiceStatus": map[string]any{"RunningTasks": running, "DesiredTasks": desired},
	}
	if update != nil {
		s["UpdateStatus"] = update
	}
	return s
}

// postDocker runs one Docker check against a handler wired to the fake
// Engine's socket.
func postDocker(t *testing.T, socket, action, parameters string) agent.Response {
	t.Helper()
	body, _ := json.Marshal(agent.Request{Parameters: parameters})
	req := httptest.NewRequest("POST", "/"+action, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	Handler(Config{Key: testKey, DockerSocket: socket}, slog.New(slog.DiscardHandler)).ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("%s: status = %d", action, rec.Code)
	}
	var resp agent.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSwarmServiceCheck(t *testing.T) {
	engine := &fakeEngine{services: []map[string]any{
		service("web", 3, 3, "replicated", nil),
		service("web-canary", 1, 2, "replicated", nil),
		service("api", 0, 2, "replicated", nil),
		service("idle", 0, 0, "replicated", nil),
		service("agent", 4, 4, "global", nil),
		service("stuck", 3, 3, "replicated", map[string]any{"State": "paused", "Message": "update paused due to failure or early termination of task abc"}),
		service("stuck-down", 0, 3, "replicated", map[string]any{"State": "paused", "Message": "update paused due to failure or early termination of task def"}),
	}}
	sock := engine.serve(t)

	for _, tc := range []struct {
		name, service string
		want          int
		msg           string
	}{
		{"every replica running", "web", agent.StatusHealthy, "3 of 3 replicas running"},
		{"some replicas running", "web-canary", agent.StatusWarning, "1 of 2 replicas running"},
		{"no replicas running", "api", agent.StatusProblem, "0 of 2 replicas running"},
		{"scaled to zero", "idle", agent.StatusWarning, "scaled to 0"},
		{"global mode counts nodes", "agent", agent.StatusHealthy, "4 of 4 nodes running"},
		{"a paused update is a warning even with every replica up", "stuck", agent.StatusWarning, "update paused"},
		{"a paused update does not hide an outage", "stuck-down", agent.StatusProblem, "0 of 3 replicas running (update paused"},
		{"a service that does not exist is a problem", "nope", agent.StatusProblem, "no service named nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postDocker(t, sock, "swarm-service", "service="+tc.service)
			if resp.NewStatusID != tc.want || !strings.Contains(resp.Status, tc.msg) {
				t.Errorf("status = %d (%q), want %d containing %q", resp.NewStatusID, resp.Status, tc.want, tc.msg)
			}
			if resp.Measurement != nil {
				t.Error("a verdict check reported a measurement")
			}
		})
	}

	// "web" must not match "web-canary": the Engine's filter is a prefix
	// match and the check has to pick the exact name out of what comes back.
	t.Run("the name is matched exactly, not as a prefix", func(t *testing.T) {
		engine.services = []map[string]any{service("web-canary", 1, 2, "replicated", nil)}
		resp := postDocker(t, sock, "swarm-service", "service=web")
		if resp.NewStatusID != agent.StatusProblem {
			t.Errorf("status = %d (%q), want problem: web-canary is not web", resp.NewStatusID, resp.Status)
		}
	})

	t.Run("an engine too old to report status has its tasks counted", func(t *testing.T) {
		svc := service("old", 0, 0, "replicated", nil)
		delete(svc, "ServiceStatus")
		engine.services = []map[string]any{svc}
		engine.tasks = []map[string]any{
			{"DesiredState": "running", "Status": map[string]any{"State": "running"}},
			{"DesiredState": "running", "Status": map[string]any{"State": "starting"}},
			{"DesiredState": "shutdown", "Status": map[string]any{"State": "shutdown"}},
		}
		resp := postDocker(t, sock, "swarm-service", "service=old")
		if resp.NewStatusID != agent.StatusWarning || !strings.Contains(resp.Status, "1 of 2") {
			t.Errorf("status = %d (%q), want warning with 1 of 2", resp.NewStatusID, resp.Status)
		}
	})

	t.Run("a worker says it is not a manager rather than reporting an outage", func(t *testing.T) {
		engine.notManager = true
		resp := postDocker(t, sock, "swarm-service", "service=web")
		if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "not a Swarm manager") {
			t.Errorf("status = %d (%q), want unknown naming the manager", resp.NewStatusID, resp.Status)
		}
	})

	t.Run("no service is unknown", func(t *testing.T) {
		resp := postDocker(t, sock, "swarm-service", "")
		if resp.NewStatusID != agent.StatusUnknown {
			t.Errorf("status = %d (%q), want unknown", resp.NewStatusID, resp.Status)
		}
	})
}

func TestContainerCheck(t *testing.T) {
	exited := running("exited", nil)
	exited["State"].(map[string]any)["ExitCode"] = 137
	exited["State"].(map[string]any)["OOMKilled"] = true
	exited["RestartCount"] = 5

	engine := &fakeEngine{containers: map[string]map[string]any{
		"plain":     running("running", nil),
		"healthy":   running("running", map[string]any{"Status": "healthy"}),
		"starting":  running("running", map[string]any{"Status": "starting"}),
		"unhealthy": running("running", map[string]any{"Status": "unhealthy", "FailingStreak": 4, "Log": []map[string]any{{"ExitCode": 1, "Output": "curl: (7) Failed to connect\nmore"}}}),
		"paused":    running("paused", nil),
		"looping":   running("restarting", nil),
		"exited":    exited,
	}}
	sock := engine.serve(t)

	for _, tc := range []struct {
		container string
		want      int
		msg       string
	}{
		{"plain", agent.StatusHealthy, "running for"},
		{"healthy", agent.StatusHealthy, "healthcheck passing"},
		{"starting", agent.StatusWarning, "still starting"},
		{"unhealthy", agent.StatusProblem, "failed 4 times in a row: curl: (7) Failed to connect"},
		{"paused", agent.StatusWarning, "paused"},
		{"looping", agent.StatusProblem, "restarting"},
		{"exited", agent.StatusProblem, "exited with code 137, restarted 5 times, killed for exceeding its memory limit"},
		{"nope", agent.StatusProblem, "no container named nope on this node"},
	} {
		t.Run(tc.container, func(t *testing.T) {
			resp := postDocker(t, sock, "container", "container="+tc.container)
			if resp.NewStatusID != tc.want || !strings.Contains(resp.Status, tc.msg) {
				t.Errorf("status = %d (%q), want %d containing %q", resp.NewStatusID, resp.Status, tc.want, tc.msg)
			}
		})
	}

	// A name is placed in a URL path; one that is not a name Docker would
	// accept is refused before it gets there.
	t.Run("a name that is not a container name is refused", func(t *testing.T) {
		for _, bad := range []string{"../services", "a/b", "-x", "a b", ""} {
			resp := postDocker(t, sock, "container", "container="+strings.ReplaceAll(bad, " ", "%20"))
			if resp.NewStatusID != agent.StatusUnknown {
				t.Errorf("%q: status = %d (%q), want unknown", bad, resp.NewStatusID, resp.Status)
			}
		}
	})

	t.Run("no engine is unknown and says where it looked", func(t *testing.T) {
		resp := postDocker(t, sock+".missing", "container", "container=plain")
		if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, sock+".missing") {
			t.Errorf("status = %d (%q), want unknown naming the socket", resp.NewStatusID, resp.Status)
		}
	})
}

func TestContainerSensors(t *testing.T) {
	limited := running("running", nil)
	limited["HostConfig"] = map[string]any{"Memory": 64 << 20, "NanoCpus": 500_000_000}
	quota := running("running", nil)
	quota["HostConfig"] = map[string]any{"CpuQuota": 200000, "CpuPeriod": 100000}

	// One second of Engine samples on a four-core node: the container used a
	// quarter of the node, which is one whole core.
	cpu := map[string]any{
		"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 2_000_000_000}, "system_cpu_usage": 8_000_000_000, "online_cpus": 4},
		"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 1_000_000_000}, "system_cpu_usage": 4_000_000_000},
		// 32 MiB in use of which 8 MiB is page cache.
		"memory_stats": map[string]any{"usage": 32 << 20, "limit": 64 << 20, "stats": map[string]any{"inactive_file": 8 << 20}},
	}
	unlimitedMem := map[string]any{
		"cpu_stats":    cpu["cpu_stats"],
		"precpu_stats": cpu["precpu_stats"],
		"memory_stats": map[string]any{"usage": 1 << 30, "limit": 16 << 30, "stats": map[string]any{"total_inactive_file": 0}},
	}

	engine := &fakeEngine{
		containers: map[string]map[string]any{"limited": limited, "free": running("running", nil), "quota": quota, "stopped": running("exited", nil)},
		stats:      map[string]map[string]any{"limited": cpu, "free": unlimitedMem, "quota": cpu, "stopped": {}},
	}
	sock := engine.serve(t)

	measurement := func(t *testing.T, action, container string) (float64, string) {
		t.Helper()
		resp := postDocker(t, sock, action, "container="+container)
		if resp.Measurement == nil {
			t.Fatalf("%s %s: no measurement: %d %q", action, container, resp.NewStatusID, resp.Status)
		}
		if resp.NewStatusID != 0 {
			t.Errorf("%s %s: a sensor gave a verdict (%d); that is the server's to make", action, container, resp.NewStatusID)
		}
		return *resp.Measurement, resp.Status
	}

	t.Run("memory is a percentage of the limit with the page cache left out", func(t *testing.T) {
		got, msg := measurement(t, "container-memory", "limited")
		if got != 37.5 || !strings.Contains(msg, "of its 64.0 MiB limit") {
			t.Errorf("got %v %q, want 37.5 of the 64 MiB limit", got, msg)
		}
	})
	t.Run("memory without a limit is of the node and says so", func(t *testing.T) {
		got, msg := measurement(t, "container-memory", "free")
		if got != 6.25 || !strings.Contains(msg, "no memory limit") {
			t.Errorf("got %v %q, want 6.25 with no limit named", got, msg)
		}
	})
	t.Run("cpu is a percentage of the limit", func(t *testing.T) {
		got, msg := measurement(t, "container-cpu", "limited")
		if got != 200 || !strings.Contains(msg, "of its 0.5 CPU limit") {
			t.Errorf("got %v %q, want 200 of the half-core limit", got, msg)
		}
	})
	t.Run("a quota and period are a limit too", func(t *testing.T) {
		got, msg := measurement(t, "container-cpu", "quota")
		if got != 50 || !strings.Contains(msg, "of its 2 CPU limit") {
			t.Errorf("got %v %q, want 50 of the two-core limit", got, msg)
		}
	})
	t.Run("cpu without a limit is of the whole node", func(t *testing.T) {
		got, msg := measurement(t, "container-cpu", "free")
		if got != 25 || !strings.Contains(msg, "node's 4 CPUs (no CPU limit)") {
			t.Errorf("got %v %q, want 25 of the node", got, msg)
		}
	})
	t.Run("a container that is not running cannot be measured", func(t *testing.T) {
		for _, action := range []string{"container-memory", "container-cpu"} {
			resp := postDocker(t, sock, action, "container=stopped")
			if resp.NewStatusID != agent.StatusUnknown || resp.Measurement != nil {
				t.Errorf("%s: status = %d (%q), want unknown and no reading", action, resp.NewStatusID, resp.Status)
			}
		}
	})
	t.Run("a missing container cannot be measured either", func(t *testing.T) {
		resp := postDocker(t, sock, "container-memory", "container=nope")
		if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "no container named nope") {
			t.Errorf("status = %d (%q), want unknown naming the container", resp.NewStatusID, resp.Status)
		}
	})
}

func TestSwarmStackCheck(t *testing.T) {
	engine := &fakeEngine{services: []map[string]any{
		service("shop_web", 3, 3, "replicated", nil),
		service("shop_api", 1, 2, "replicated", nil),
		service("shop_worker", 0, 2, "replicated", nil),
		service("shop_agent", 4, 4, "global", nil),
		service("other_web", 1, 1, "replicated", nil),
		service("dead_a", 0, 1, "replicated", nil),
		service("dead_b", 0, 3, "replicated", nil),
		service("fine_a", 1, 1, "replicated", nil),
		service("fine_b", 2, 2, "replicated", nil),
	}}
	sock := engine.serve(t)

	for _, tc := range []struct {
		name, stack string
		want        int
		msg         string
	}{
		{"every service whole", "fine", agent.StatusHealthy, "fine: 2 of 2 services fully running"},
		{"some services short, named without the stack prefix", "shop", agent.StatusWarning,
			"shop: 2 of 4 services fully running (api 1/2, worker 0/2)"},
		{"nothing running at all", "dead", agent.StatusProblem, "dead: 0 of 2 services fully running (a 0/1, b 0/3)"},
		{"a stack that does not exist", "nope", agent.StatusProblem, "no stack named nope"},
		// "other" must not pull in "other_web" by prefix on the stack name
		// alone; the label is the match, and "oth" is not a stack.
		{"the label is an exact match", "oth", agent.StatusProblem, "no stack named oth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postDocker(t, sock, "swarm-stack", "stack="+tc.stack)
			if resp.NewStatusID != tc.want || !strings.Contains(resp.Status, tc.msg) {
				t.Errorf("status = %d (%q), want %d containing %q", resp.NewStatusID, resp.Status, tc.want, tc.msg)
			}
		})
	}

	t.Run("a worker says it is not a manager", func(t *testing.T) {
		engine.notManager = true
		resp := postDocker(t, sock, "swarm-stack", "stack=shop")
		if resp.NewStatusID != agent.StatusUnknown || !strings.Contains(resp.Status, "not a Swarm manager") {
			t.Errorf("status = %d (%q), want unknown naming the manager", resp.NewStatusID, resp.Status)
		}
	})
}
