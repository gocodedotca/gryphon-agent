package clientagent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// fakeAPI is enough of the Kubernetes API server for the checks: objects by
// path, lists by path with optional paging, and the token check a real one
// makes. It serves TLS with a certificate the client is given as its
// ServiceAccount CA, so the client's trust and auth are exercised and not
// just its parsing.
type fakeAPI struct {
	mu sync.Mutex
	// objects answers a get, by path.
	objects map[string]any
	// lists answers a list, by path: every item, served pageSize at a time
	// when pageSize is set.
	lists    map[string][]any
	pageSize int
	// status, by path, answers with that code and a Status body instead.
	status map[string]int
	// token is what the server accepts, read from the file each time so a
	// test can rotate it.
	tokenFile string
	// seen is every request's path and query, in order.
	seen []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.URL.RequestURI())

	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	want, _ := os.ReadFile(f.tokenFile)
	if r.Header.Get("Authorization") != "Bearer "+strings.TrimSpace(string(want)) {
		reply(401, map[string]any{"kind": "Status", "reason": "Unauthorized", "message": "Unauthorized"})
		return
	}
	if code, ok := f.status[r.URL.Path]; ok {
		reply(code, map[string]any{"kind": "Status", "reason": http.StatusText(code), "message": "refused by the test"})
		return
	}
	if obj, ok := f.objects[r.URL.Path]; ok {
		reply(200, obj)
		return
	}
	items, ok := f.lists[r.URL.Path]
	if !ok {
		reply(404, map[string]any{"kind": "Status", "reason": "NotFound", "message": "not found"})
		return
	}
	start := 0
	if c := r.URL.Query().Get("continue"); c != "" {
		fmt.Sscan(c, &start)
	}
	end := len(items)
	next := ""
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
		next = fmt.Sprint(end)
	}
	if items == nil {
		items = []any{}
	}
	reply(200, map[string]any{"metadata": map[string]any{"continue": next}, "items": items[start:end]})
}

// kubeEnv is a fake API server and a client for it, as a pod would have.
type kubeEnv struct {
	api  *fakeAPI
	kube *kubeClient
	dir  string
}

func newKubeEnv(t *testing.T) *kubeEnv {
	t.Helper()
	dir := t.TempDir()
	api := &fakeAPI{objects: map[string]any{}, lists: map[string][]any{}, status: map[string]int{},
		tokenFile: filepath.Join(dir, "token")}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	for name, body := range map[string]string{"ca.crt": string(ca), "token": "first-token", "namespace": "gryphon\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	env := map[string]string{"KUBERNETES_SERVICE_HOST": host, "KUBERNETES_SERVICE_PORT": port}
	k := newKubeClient(func(k string) string { return env[k] }, "node-a", dir)
	if k == nil {
		t.Fatal("newKubeClient found no cluster in a complete pod environment")
	}
	return &kubeEnv{api: api, kube: k, dir: dir}
}

// at stands the clock at t for the rest of the test.
func at(t *testing.T, when time.Time) {
	t.Helper()
	old := kubeNow
	kubeNow = func() time.Time { return when }
	t.Cleanup(func() { kubeNow = old })
}

func wantResult(t *testing.T, r result, status int, contains ...string) {
	t.Helper()
	if r.statusID != status {
		t.Errorf("status = %d, want %d (%s)", r.statusID, status, r.msg)
	}
	for _, c := range contains {
		if !strings.Contains(r.msg, c) {
			t.Errorf("message %q does not contain %q", r.msg, c)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func deployment(name string, replicas *int32, ready int32, conds ...map[string]string) map[string]any {
	spec := map[string]any{}
	if replicas != nil {
		spec["replicas"] = *replicas
	}
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "shop"},
		"spec":     spec,
		"status":   map[string]any{"readyReplicas": ready, "conditions": conds},
	}
}

const shopDeployments = "/apis/apps/v1/namespaces/shop/deployments"

func TestNotInACluster(t *testing.T) {
	if k := newKubeClient(func(string) string { return "" }, "", t.TempDir()); k != nil {
		t.Fatal("a client without KUBERNETES_SERVICE_HOST")
	}
	env := func(k string) string { return map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}[k] }
	if k := newKubeClient(env, "", t.TempDir()); k != nil {
		t.Fatal("a client without a mounted ServiceAccount")
	}

	h := newHandlers(Config{}.withDefaults(), slog.New(slog.DiscardHandler))
	if slices.Contains(h.checkNames(), "k8s-workload") {
		t.Error("an agent outside a cluster offers the Kubernetes checks")
	}
	if code, _ := h.run(context.Background(), "k8s-workload", "namespace=shop&name=web"); code != http.StatusNotFound {
		t.Errorf("an agent outside a cluster answered a Kubernetes check with %d, want 404", code)
	}
}

func TestInClusterOffersTheChecksAndSaysSoInHello(t *testing.T) {
	e := newKubeEnv(t)
	e.api.objects["/version"] = map[string]string{"gitVersion": "v1.31.2"}
	h := newHandlers(Config{}.withDefaults(), slog.New(slog.DiscardHandler))
	h.kube = e.kube

	for name := range kubeChecks {
		if !slices.Contains(h.checkNames(), name) {
			t.Errorf("an agent in a cluster does not offer %s", name)
		}
	}
	hello := helloFrame(context.Background(), h).Hello
	if hello.Kubernetes == nil {
		t.Fatal("no Kubernetes block in the hello")
	}
	if got := *hello.Kubernetes; got != (agent.KubernetesInfo{Version: "v1.31.2", Namespace: "gryphon", Node: "node-a"}) {
		t.Errorf("hello says %+v", got)
	}
}

func TestHelloWithoutAVersionStillSaysTheRest(t *testing.T) {
	e := newKubeEnv(t)
	e.api.status["/version"] = 500
	in := e.kube.info(context.Background())
	if in.Version != "" || in.Namespace != "gryphon" {
		t.Errorf("info = %+v", in)
	}
}

func TestWorkloadDeployment(t *testing.T) {
	stuck := map[string]string{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded",
		"message": `ReplicaSet "web-7d9f" has timed out progressing.`}
	cases := []struct {
		name   string
		obj    map[string]any
		status int
		msg    []string
	}{
		{"all ready", deployment("web", ptr[int32](3), 3), agent.StatusHealthy, []string{"web: 3 of 3 replicas ready"}},
		{"short", deployment("web", ptr[int32](3), 2), agent.StatusWarning, []string{"2 of 3"}},
		{"none ready", deployment("web", ptr[int32](3), 0), agent.StatusProblem, []string{"0 of 3"}},
		{"scaled to zero", deployment("web", ptr[int32](0), 0), agent.StatusWarning, []string{"scaled to 0"}},
		{"replicas absent means one", deployment("web", nil, 1), agent.StatusHealthy, []string{"1 of 1"}},
		{"stuck but serving", deployment("web", ptr[int32](3), 3, stuck), agent.StatusWarning, []string{"rollout stuck", "timed out progressing"}},
		{"stuck and down", deployment("web", ptr[int32](3), 0, stuck), agent.StatusProblem, []string{"rollout stuck"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newKubeEnv(t)
			e.api.objects[shopDeployments+"/web"] = c.obj
			r := e.kube.checkWorkload(context.Background(), "namespace=shop&kind=deployment&name=web")
			wantResult(t, r, c.status, c.msg...)
		})
	}
}

func TestWorkloadOtherKindsAndMistakes(t *testing.T) {
	e := newKubeEnv(t)
	e.api.objects["/apis/apps/v1/namespaces/shop/daemonsets/fluentd"] = map[string]any{
		"metadata": map[string]any{"name": "fluentd"},
		"status":   map[string]any{"desiredNumberScheduled": 3, "numberReady": 2},
	}
	e.api.objects["/apis/apps/v1/namespaces/shop/statefulsets/db"] = map[string]any{
		"metadata": map[string]any{"name": "db"},
		"spec":     map[string]any{"replicas": 2},
		"status":   map[string]any{"readyReplicas": 2},
	}
	ctx := context.Background()

	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&kind=DaemonSet&name=fluentd"),
		agent.StatusWarning, "fluentd: 2 of 3 nodes ready")
	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&kind=statefulset&name=db"),
		agent.StatusHealthy, "db: 2 of 2 replicas ready")
	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&kind=deployment&name=gone"),
		agent.StatusProblem, "no deployment named gone in namespace shop")
	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&kind=pod&name=web"),
		agent.StatusUnknown, "not a kind this check reads")

	before := len(e.api.seen)
	for _, bad := range []string{
		"namespace=shop&name=../../api/v1/secrets",
		"namespace=Shop&name=web",
		"namespace=shop%2Fx&name=web",
		"name=web",
		"namespace=shop",
	} {
		r := e.kube.checkWorkload(ctx, bad)
		if r.statusID != agent.StatusUnknown {
			t.Errorf("%s: status %d (%s), want unknown", bad, r.statusID, r.msg)
		}
	}
	if len(e.api.seen) != before {
		t.Errorf("a name Kubernetes would refuse reached the API: %v", e.api.seen[before:])
	}
}

func TestRefusalsSayWhatToFix(t *testing.T) {
	e := newKubeEnv(t)
	e.api.status[shopDeployments+"/web"] = 403
	r := e.kube.checkWorkload(context.Background(), "namespace=shop&name=web")
	wantResult(t, r, agent.StatusUnknown, "may not get deployments in namespace shop", "apply gryphon-agent-role.yaml in shop")

	e.api.status["/api/v1/nodes"] = 403
	r = e.kube.checkNodes(context.Background(), "")
	wantResult(t, r, agent.StatusUnknown, "may not list nodes across the cluster", "apply gryphon-agent.yaml")

	os.WriteFile(filepath.Join(e.dir, "token"), []byte("revoked"), 0o600)
	e.api.tokenFile = filepath.Join(t.TempDir(), "other")
	os.WriteFile(e.api.tokenFile, []byte("current"), 0o600)
	r = e.kube.checkWorkload(context.Background(), "namespace=shop&name=web")
	wantResult(t, r, agent.StatusUnknown, "refused the agent's ServiceAccount token")
}

func TestTokenIsReadAfresh(t *testing.T) {
	e := newKubeEnv(t)
	e.api.objects[shopDeployments+"/web"] = deployment("web", ptr[int32](1), 1)
	ctx := context.Background()
	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&name=web"), agent.StatusHealthy)

	// The kubelet rotates the token by rewriting the file; the server
	// stops taking the old one.
	if err := os.WriteFile(filepath.Join(e.dir, "token"), []byte("second-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantResult(t, e.kube.checkWorkload(ctx, "namespace=shop&name=web"), agent.StatusHealthy)
}

func TestApp(t *testing.T) {
	e := newKubeEnv(t)
	e.api.pageSize = 2 // three deployments: two pages
	e.api.lists[shopDeployments] = []any{
		deployment("web", ptr[int32](3), 3),
		deployment("api", ptr[int32](2), 1),
		deployment("worker", ptr[int32](1), 1),
	}
	e.api.lists["/apis/apps/v1/namespaces/shop/statefulsets"] = []any{map[string]any{
		"metadata": map[string]any{"name": "db"}, "spec": map[string]any{"replicas": 1}, "status": map[string]any{"readyReplicas": 1},
	}}
	e.api.lists["/apis/apps/v1/namespaces/shop/daemonsets"] = nil
	old := kubePageSize
	kubePageSize = 2
	t.Cleanup(func() { kubePageSize = old })

	r := e.kube.checkApp(context.Background(), "namespace=shop&selector=app.kubernetes.io%2Fpart-of%3Dshop")
	wantResult(t, r, agent.StatusWarning,
		"app.kubernetes.io/part-of=shop in shop: 3 of 4 workloads fully ready", "deployment/api 1/2")
	if r.data != "3|4" {
		t.Errorf("data = %q", r.data)
	}

	var sawSelector, sawContinue bool
	for _, s := range e.api.seen {
		u, _ := url.Parse(s)
		if u.Query().Get("labelSelector") == "app.kubernetes.io/part-of=shop" {
			sawSelector = true
		}
		if u.Path == shopDeployments && u.Query().Get("continue") == "2" {
			sawContinue = true
		}
	}
	if !sawSelector || !sawContinue {
		t.Errorf("selector sent %v, second page asked for %v: %v", sawSelector, sawContinue, e.api.seen)
	}
}

func TestAppWithNothingMatchingIsAProblem(t *testing.T) {
	e := newKubeEnv(t)
	for _, k := range []string{"deployments", "statefulsets", "daemonsets"} {
		e.api.lists["/apis/apps/v1/namespaces/shop/"+k] = nil
	}
	r := e.kube.checkApp(context.Background(), "namespace=shop&selector=app%3Dshpo")
	wantResult(t, r, agent.StatusProblem, "no deployments, statefulsets or daemonsets match app=shpo in shop")
}

func TestAppAllDownAndStuck(t *testing.T) {
	e := newKubeEnv(t)
	e.api.lists[shopDeployments] = []any{
		deployment("web", ptr[int32](2), 0),
		deployment("api", ptr[int32](2), 0),
	}
	e.api.lists["/apis/apps/v1/namespaces/shop/statefulsets"] = nil
	e.api.lists["/apis/apps/v1/namespaces/shop/daemonsets"] = nil
	wantResult(t, e.kube.checkApp(context.Background(), "namespace=shop"), agent.StatusProblem, "0 of 2")

	e.api.lists[shopDeployments] = []any{deployment("web", ptr[int32](2), 2,
		map[string]string{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"})}
	wantResult(t, e.kube.checkApp(context.Background(), "namespace=shop"), agent.StatusWarning, "rollout stuck: deployment/web")
}

func node(name string, ready string, unschedulable bool, pressures ...string) map[string]any {
	conds := []map[string]string{{"type": "Ready", "status": ready}}
	for _, p := range pressures {
		conds = append(conds, map[string]string{"type": p, "status": "True"})
	}
	conds = append(conds, map[string]string{"type": "DiskPressure", "status": "False"})
	return map[string]any{
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"unschedulable": unschedulable},
		"status":   map[string]any{"conditions": conds},
	}
}

func TestNodes(t *testing.T) {
	cases := []struct {
		name   string
		nodes  []any
		status int
		msg    []string
	}{
		{"all ready", []any{node("a", "True", false), node("b", "True", false)}, agent.StatusHealthy, []string{"2 of 2 nodes ready"}},
		{"one not ready", []any{node("a", "True", false), node("b", "Unknown", false)}, agent.StatusWarning, []string{"1 of 2", "not ready: b"}},
		{"none ready", []any{node("a", "False", false)}, agent.StatusProblem, []string{"0 of 1"}},
		{"pressure", []any{node("a", "True", false, "MemoryPressure", "PIDPressure")}, agent.StatusWarning, []string{"under pressure: a MemoryPressure+PIDPressure"}},
		{"cordoned is said, not graded", []any{node("a", "True", true), node("b", "True", false)}, agent.StatusHealthy, []string{"cordoned: a"}},
		{"none at all", nil, agent.StatusProblem, []string{"no nodes"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newKubeEnv(t)
			e.api.lists["/api/v1/nodes"] = c.nodes
			wantResult(t, e.kube.checkNodes(context.Background(), ""), c.status, c.msg...)
		})
	}
}

func pod(name, phase string, statuses ...map[string]any) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name},
		"status":   map[string]any{"phase": phase, "containerStatuses": statuses},
	}
}

func container(name string, restarts int, waiting string, lastFinished time.Time) map[string]any {
	c := map[string]any{"name": name, "restartCount": restarts, "state": map[string]any{}, "lastState": map[string]any{}}
	if waiting != "" {
		c["state"] = map[string]any{"waiting": map[string]any{"reason": waiting}}
	} else {
		c["state"] = map[string]any{"running": map[string]any{}}
	}
	if !lastFinished.IsZero() {
		c["lastState"] = map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 1, "finishedAt": lastFinished}}
	}
	return c
}

func TestPods(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	const path = "/api/v1/namespaces/shop/pods"
	cases := []struct {
		name   string
		params string
		pods   []any
		status int
		msg    []string
	}{
		{"quiet", "namespace=shop", []any{pod("web-1", "Running", container("app", 0, "", time.Time{}))},
			agent.StatusHealthy, []string{"1 pods, none crash-looping"}},
		{"crash loop", "namespace=shop", []any{
			pod("web-1", "Running", container("app", 14, "CrashLoopBackOff", now.Add(-time.Minute))),
			pod("web-2", "Running", container("app", 0, "", time.Time{})),
		}, agent.StatusProblem, []string{"1 of 2 pods", "web-1/app CrashLoopBackOff (14 restarts)"}},
		{"caught between two crashes", "namespace=shop", []any{pod("web-1", "Running", map[string]any{
			"name": "app", "restartCount": 3, "lastState": map[string]any{},
			"state": map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 1, "finishedAt": now.Add(-time.Second)}}})},
			agent.StatusProblem, []string{"web-1/app exited 1, Error (3 restarts)"}},
		{"its first exit, not yet restarted", "namespace=shop", []any{pod("web-1", "Running", map[string]any{
			"name": "app", "restartCount": 0, "lastState": map[string]any{},
			"state": map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 1, "finishedAt": now.Add(-time.Second)}}})},
			agent.StatusHealthy, nil},
		{"cannot pull", "namespace=shop", []any{pod("web-1", "Pending", container("app", 0, "ImagePullBackOff", time.Time{}))},
			agent.StatusProblem, []string{"ImagePullBackOff"}},
		{"restarting recently", "namespace=shop", []any{pod("web-1", "Running", container("app", 9, "", now.Add(-10*time.Minute)))},
			agent.StatusWarning, []string{"web-1/app 9 restarts, last 10m ago"}},
		{"old restarts are history", "namespace=shop", []any{pod("web-1", "Running", container("app", 40, "", now.Add(-72*time.Hour)))},
			agent.StatusHealthy, nil},
		{"a wider window catches them", "namespace=shop&window=10000", []any{pod("web-1", "Running", container("app", 40, "", now.Add(-72*time.Hour)))},
			agent.StatusWarning, nil},
		{"a lower threshold", "namespace=shop&restarts=1", []any{pod("web-1", "Running", container("app", 2, "", now.Add(-time.Minute)))},
			agent.StatusWarning, nil},
		{"finished pods are ignored", "namespace=shop", []any{
			pod("job-1", "Failed", container("run", 0, "CrashLoopBackOff", time.Time{})),
			pod("job-2", "Succeeded", container("run", 0, "", time.Time{})),
		}, agent.StatusHealthy, []string{"no running pods match namespace shop"}},
		{"a bad setting", "namespace=shop&restarts=many", nil, agent.StatusUnknown, []string{`"many" is not a whole number`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newKubeEnv(t)
			at(t, now)
			e.api.lists[path] = c.pods
			wantResult(t, e.kube.checkPods(context.Background(), c.params), c.status, c.msg...)
		})
	}
}

func cronJob(schedule, tz string, created time.Time, lastSuccess *time.Time, active int, suspend bool) map[string]any {
	spec := map[string]any{"schedule": schedule, "suspend": suspend}
	if tz != "" {
		spec["timeZone"] = tz
	}
	status := map[string]any{"active": make([]map[string]string, active)}
	if lastSuccess != nil {
		status["lastSuccessfulTime"] = *lastSuccess
	}
	return map[string]any{
		"metadata": map[string]any{"name": "backup", "creationTimestamp": created},
		"spec":     spec,
		"status":   status,
	}
}

func TestCronJob(t *testing.T) {
	const path = "/apis/batch/v1/namespaces/ops/cronjobs/backup"
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, time.UTC) }

	cases := []struct {
		name   string
		obj    map[string]any
		now    time.Time
		status int
		msg    []string
	}{
		{"on time", cronJob("0 2 * * *", "", created, ptr(day(6, 2, 5)), 0, false), day(6, 12, 0),
			agent.StatusHealthy, []string{"last succeeded 9h 55m ago", "next run 2026-10-07 02:00 UTC"}},
		{"due but within grace", cronJob("0 2 * * *", "", created, ptr(day(5, 2, 5)), 0, false), day(6, 2, 1),
			agent.StatusHealthy, nil},
		{"running now", cronJob("0 2 * * *", "", created, ptr(day(5, 2, 5)), 1, false), day(6, 3, 0),
			agent.StatusHealthy, []string{"the run due 2026-10-06 02:00 UTC is running"}},
		{"one run missed", cronJob("0 2 * * *", "", created, ptr(day(5, 2, 5)), 0, false), day(6, 3, 0),
			agent.StatusWarning, []string{"the run due 2026-10-06 02:00 UTC has not succeeded"}},
		{"two runs missed", cronJob("0 2 * * *", "", created, ptr(day(4, 2, 5)), 0, false), day(6, 3, 0),
			agent.StatusProblem, []string{"2 scheduled runs have passed", "the first was due 2026-10-05 02:00 UTC"}},
		{"many missed", cronJob("* * * * *", "", created, ptr(day(1, 0, 0)), 0, false), day(6, 3, 0),
			agent.StatusProblem, []string{"3 or more scheduled runs"}},
		{"never run, none due", cronJob("0 2 * * *", "", day(6, 3, 0), nil, 0, false), day(6, 12, 0),
			agent.StatusHealthy, []string{"no run due yet"}},
		{"never succeeded", cronJob("0 2 * * *", "", day(4, 3, 0), nil, 0, false), day(6, 12, 0),
			agent.StatusProblem, []string{"since it was created"}},
		{"suspended", cronJob("0 2 * * *", "", created, ptr(day(6, 2, 5)), 0, true), day(6, 12, 0),
			agent.StatusProblem, []string{"suspended"}},
		{"unreadable schedule", cronJob("every day", "", created, nil, 0, false), day(6, 12, 0),
			agent.StatusUnknown, []string{"cannot read its schedule"}},
		{"unknown time zone", cronJob("0 2 * * *", "Mars/Olympus", created, nil, 0, false), day(6, 12, 0),
			agent.StatusUnknown, []string{"cannot read its time zone"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newKubeEnv(t)
			at(t, c.now)
			e.api.objects[path] = c.obj
			wantResult(t, e.kube.checkCronJob(context.Background(), "namespace=ops&name=backup"), c.status, c.msg...)
		})
	}

	e := newKubeEnv(t)
	wantResult(t, e.kube.checkCronJob(context.Background(), "namespace=ops&name=backup"),
		agent.StatusProblem, "no CronJob named backup in namespace ops")
}

// A daily 09:00 job in Toronto, the day the clocks go forward: 09:00 EDT
// comes 23 hours after 09:00 EST. A schedule read in UTC would put the run at
// 10:00 local and not call it missed until then.
func TestCronJobAcrossDaylightSaving(t *testing.T) {
	toronto, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Skip("no time zone data:", err)
	}
	e := newKubeEnv(t)
	last := time.Date(2026, 3, 7, 9, 1, 0, 0, toronto)
	e.api.objects["/apis/batch/v1/namespaces/ops/cronjobs/backup"] =
		cronJob("0 9 * * *", "America/Toronto", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), &last, 0, false)

	at(t, time.Date(2026, 3, 8, 9, 5, 0, 0, toronto))
	wantResult(t, e.kube.checkCronJob(context.Background(), "namespace=ops&name=backup"),
		agent.StatusWarning, "the run due 2026-03-08 09:00 EDT has not succeeded")
}

func TestListRefusesAnEndlessAnswer(t *testing.T) {
	e := newKubeEnv(t)
	e.api.pageSize = 1
	items := make([]any, kubeMaxPages+1)
	for i := range items {
		items[i] = node(fmt.Sprint("n", i), "True", false)
	}
	e.api.lists["/api/v1/nodes"] = items
	old := kubePageSize
	kubePageSize = 1
	t.Cleanup(func() { kubePageSize = old })
	wantResult(t, e.kube.checkNodes(context.Background(), ""), agent.StatusUnknown, "narrow the check with a selector")
}

func TestKubeChecksRunThroughTheAgent(t *testing.T) {
	e := newKubeEnv(t)
	e.api.objects[shopDeployments+"/web"] = deployment("web", ptr[int32](2), 2)
	h := newHandlers(Config{}.withDefaults(), slog.New(slog.DiscardHandler))
	h.kube = e.kube
	code, resp := h.run(context.Background(), "k8s-workload", "namespace=shop&name=web")
	if code != http.StatusOK || resp.NewStatusID != agent.StatusHealthy || !resp.OK || resp.Data != "2|2" {
		t.Errorf("run = %d %+v", code, resp)
	}
}
