package clientagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/ratelimit"
	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

// handlers is the HTTP side of the agent: the access key and the routes.
type handlers struct {
	cfg     Config
	log     *slog.Logger
	docker  *dockerClient
	scripts *scriptRunner
	files   *fileWatcher
	net     *netProbe
	// slots bounds the checks in flight; see Config.MaxConcurrent.
	slots chan struct{}
	// denials throttles a caller that keeps presenting a wrong key.
	denials *ratelimit.Memory
}

// Wrong keys are counted per caller: past this many in the window, the
// caller is answered 429 until the window ends. Sixty a minute is more than
// a misconfigured server with a host full of checks produces -- so the right
// key, once saved, is not made to wait -- and a guess at a 256-bit key
// needs so many more that the limit's exact value is beside the point.
const (
	denialLimit  = 60
	denialWindow = time.Minute
)

// Handler returns the agent's HTTP handler for cfg. Most callers want Agent,
// which also owns the listener; this is for embedding the agent in another
// server, and for tests.
func Handler(cfg Config, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return newHandlers(cfg.withDefaults(), log).routes()
}

// newHandlers builds the handlers for a configuration that already has its
// defaults, with the Engine client the Docker checks need.
func newHandlers(cfg Config, log *slog.Logger) *handlers {
	return &handlers{
		cfg:     cfg,
		log:     log,
		docker:  newDockerClient(cfg.DockerSocket),
		scripts: newScriptRunner(cfg.ScriptsDir),
		files:   newFileWatcher(cfg.WatchDirs),
		net:     newNetProbe(cfg.reach()),
		slots:   make(chan struct{}, cfg.MaxConcurrent),
		denials: ratelimit.New(denialLimit, denialWindow),
	}
}

// checkNames is every check this agent answers, for /test and for a refusal.
func (app *handlers) checkNames() []string {
	names := make([]string, 0, len(checkFuncs)+len(netChecks)+len(dockerChecks)+1)
	for name := range checkFuncs {
		names = append(names, name)
	}
	for name := range netChecks {
		names = append(names, name)
	}
	for name := range dockerChecks {
		names = append(names, name)
	}
	if app.cfg.ScriptsDir != "" {
		names = append(names, "script")
	}
	if len(app.cfg.WatchDirs) > 0 {
		names = append(names, "file-age")
	}
	sort.Strings(names)
	return names
}

// result is what a check produces before it goes on the wire.
//
// A check reports either a verdict or a measurement, never both:
//
//   - the database and network checks are pass/fail, so they set statusID;
//     the network checks can also say warning (a ping losing packets) and
//     time the answer in rtt. The swarm-service and container checks are
//     verdicts too
//   - the four system checks and the two container sensors set measurement
//     and leave statusID zero: the verdict is the server's to make, because
//     the server holds the thresholds
//   - either kind that could not run at all sets statusID to StatusUnknown,
//     which is not the same claim as the thing being broken
//   - the file-age check is the one exception: it measures an age and may
//     also say StatusProblem, for a file that is missing or too small,
//     which no threshold on the age could make acceptable
type result struct {
	statusID    int
	msg         string
	data        string
	measurement *float64
	rtt         time.Duration
}

// measured is a sensor reading: a number, and no opinion about it.
func measured(value float64, msg, data string) result {
	return result{msg: msg, data: data, measurement: &value}
}

// unknownResult reports that the measurement itself failed — which is not the
// same claim as "the thing measured is broken".
func unknownResult(err error) result {
	return result{statusID: agent.StatusUnknown, msg: "could not measure: " + err.Error()}
}

func (app *handlers) routes() http.Handler {
	mux := chi.NewRouter()

	mux.Use(middlewareRecoverer(app.log))

	// Liveness, with no key: for a systemd watchdog or an orchestrator, which
	// have none. It says nothing but that the agent is up.
	mux.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.Group(func(mux chi.Router) {
		mux.Use(app.requireKey)
		// The server's connectivity test is a GET with no body; checks are
		// POSTs.
		mux.Get("/test", app.test)
		mux.Post("/test", app.test)
		mux.Post("/{action}", app.check)
	})

	return mux
}

// requireKey refuses any request that does not carry the access key, or the
// previous one during a rotation. The comparison is agent.KeyMatcher's; a
// handler built with no usable key refuses everything. Start will not run
// one, but Handler can be embedded directly.
//
// A caller that keeps presenting a wrong key is throttled: a misconfigured
// server sends one wrong key a minute, and a guess needs far more than the
// limit allows.
func (app *handlers) requireKey(next http.Handler) http.Handler {
	matches := agent.KeyMatcher(app.cfg.Key)
	matchesPrevious := func(string) bool { return false }
	if app.cfg.PreviousKey != "" {
		matchesPrevious = agent.KeyMatcher(app.cfg.PreviousKey)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := callerAddress(r)
		if !app.denials.Allow(caller) {
			retry := app.denials.RetryAfter(caller)
			app.log.Warn("throttled", "remote", r.RemoteAddr, "retry_after", retry)
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, agent.Response{
				OK: false, Status: "too many wrong access keys; try again later", DateTime: time.Now(),
			})
			return
		}
		presented, ok := agent.BearerToken(r)
		if !ok {
			app.deny(w, r, caller, "no access key presented")
			return
		}
		if !matches(presented) && !matchesPrevious(presented) {
			app.deny(w, r, caller, "wrong access key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// callerAddress is the address a denial is counted against: the connection's,
// which behind a reverse proxy on the same machine is loopback for everybody.
// That is still right: the throttle exists to slow a guess, and a guess
// through the proxy is slowed with everything else through it.
func callerAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// deny answers 401 with the agent's realm, which is how the server tells a
// refused key from a 401 that a proxy in front of the agent sent itself.
func (app *handlers) deny(w http.ResponseWriter, r *http.Request, caller, why string) {
	app.denials.Fail(caller)
	app.log.Warn("denied", "remote", r.RemoteAddr, "path", r.URL.Path, "reason", why)
	w.Header().Set("WWW-Authenticate", `Bearer realm="`+agent.Realm+`"`)
	writeJSON(w, http.StatusUnauthorized, agent.Response{
		OK:       false,
		Status:   "access key missing or wrong",
		DateTime: time.Now(),
		Version:  version.Version(),
	})
}

func (app *handlers) test(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, agent.Response{
		Action:      "test",
		OK:          true,
		Status:      "Success",
		DateTime:    time.Now(),
		NewStatusID: agent.StatusHealthy,
		Version:     version.Version(),
		Checks:      app.checkNames(),
	})
}

// checkFunc runs one check. ctx carries the check's deadline; a check that
// cannot honour it is still answered for when the deadline passes.
type checkFunc func(ctx context.Context, params string) result

// checkFuncs is every check that reads this machine, and needs nothing built
// from the configuration to do it.
var checkFuncs = map[string]checkFunc{
	"disk-space": func(_ context.Context, p string) result { return checkDisk(p) },
	"memory":     func(context.Context, string) result { return checkMemory() },
	"cpu":        func(context.Context, string) result { return checkCPU() },
	"load":       func(context.Context, string) result { return checkLoad() },
}

// netChecks are the checks that dial an address the server named, and so are
// held to where this agent may reach; see reach.go. Like the Docker ones they
// take the thing that was built from the configuration, rather than being bare
// functions, because that is where the rule lives.
var netChecks = map[string]func(*netProbe, context.Context, string) result{
	"postgres": (*netProbe).checkPostgres,
	"mariadb":  (*netProbe).checkMariaDB,
	"redis":    (*netProbe).checkRedis,
	"http":     func(n *netProbe, ctx context.Context, p string) result { return n.checkHTTP(ctx, "http", p) },
	"https":    func(n *netProbe, ctx context.Context, p string) result { return n.checkHTTP(ctx, "https", p) },
	"ping":     (*netProbe).checkPing,
	"tcp":      (*netProbe).checkTCP,
}

// dockerChecks are the checks that need the Engine, and so a client built from
// the configuration rather than a bare function. They are looked up after
// checkFuncs, so a path answers the same way whichever map it is in.
var dockerChecks = map[string]func(*dockerClient, context.Context, string) result{
	"swarm-service":    (*dockerClient).checkSwarmService,
	"swarm-stack":      (*dockerClient).checkSwarmStack,
	"container":        (*dockerClient).checkContainer,
	"container-memory": (*dockerClient).checkContainerMemory,
	"container-cpu":    (*dockerClient).checkContainerCPU,
}

// lookup finds the check posted to as action.
func (app *handlers) lookup(action string) (checkFunc, bool) {
	if fn, ok := checkFuncs[action]; ok {
		return fn, true
	}
	if fn, ok := netChecks[action]; ok {
		return func(ctx context.Context, params string) result { return fn(app.net, ctx, params) }, true
	}
	if fn, ok := dockerChecks[action]; ok {
		return func(ctx context.Context, params string) result { return fn(app.docker, ctx, params) }, true
	}
	if action == "script" {
		return app.scripts.check, true
	}
	if action == "file-age" {
		return app.files.check, true
	}
	return nil, false
}

// checkDeadline is agent.CheckDeadline, as a variable so a test need not wait
// fifteen seconds to see it pass.
var checkDeadline = agent.CheckDeadline

// runWithDeadline runs fn, and answers unknown if it has not finished by the
// deadline.
//
// The check is cancelled through its context, which the network and database
// checks honour. The ones that cannot be -- a disk on a hung network mount --
// are left to finish in the background, and the answer goes back regardless:
// a goroutine waiting on a syscall costs less than the server deciding the
// whole agent is down.
//
// release is called once fn has actually returned, however long that takes,
// which is what lets a slot outlive the answer.
func runWithDeadline(ctx context.Context, action, params string, fn checkFunc, release func()) result {
	ctx, cancel := context.WithTimeout(ctx, checkDeadline)
	defer cancel()

	done := make(chan result, 1)
	go func() {
		defer release()
		done <- fn(ctx, params)
	}()

	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		return result{
			statusID: agent.StatusUnknown,
			msg:      fmt.Sprintf("the %s check did not finish within %s", action, checkDeadline),
		}
	}
}

func (app *handlers) check(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")

	fn, ok := app.lookup(action)
	if !ok {
		// Named as such, with the build and what it does run, so the server
		// can say "update the agent" rather than "404".
		writeJSON(w, http.StatusNotFound, agent.Response{
			Action: action, OK: false, Status: agent.UnknownCheckStatus, DateTime: time.Now(),
			Version: version.Version(), Checks: app.checkNames(),
		})
		return
	}

	// An absent body is fine: only some checks carry parameters.
	var req agent.Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, agent.Response{
			Action: action, OK: false, Status: "could not parse request body", DateTime: time.Now(),
		})
		return
	}

	// A slot, or "busy": past the cap the agent says so rather than starting
	// one more check on a host that is already struggling. The slot is held
	// until the check itself returns, deadline or not, so a pile of stuck
	// checks fills the cap instead of the process.
	select {
	case app.slots <- struct{}{}:
	default:
		writeJSON(w, http.StatusOK, agent.Response{
			Action: action, OK: false, DateTime: time.Now(), NewStatusID: agent.StatusUnknown,
			Status:  fmt.Sprintf("the agent is busy: %d checks are already running", app.cfg.MaxConcurrent),
			Version: version.Version(),
		})
		return
	}
	res := runWithDeadline(r.Context(), action, req.Parameters, fn, func() { <-app.slots })

	writeJSON(w, http.StatusOK, agent.Response{
		Action: action,
		// OK says the agent carried the check out, not that the target is
		// healthy. For a sensor check those are different questions and only
		// the first one is the agent's to answer.
		OK:          res.measurement != nil || res.statusID == agent.StatusHealthy,
		Status:      res.msg,
		Data:        res.data,
		DateTime:    time.Now(),
		NewStatusID: res.statusID,
		Measurement: res.measurement,
		RTT:         res.rtt,
		Version:     version.Version(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v agent.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// middlewareRecoverer keeps one panicking check from taking the agent down.
func middlewareRecoverer(log interface{ Error(string, ...any) }) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
					writeJSON(w, http.StatusInternalServerError, agent.Response{
						OK: false, Status: "internal error", DateTime: time.Now(),
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
