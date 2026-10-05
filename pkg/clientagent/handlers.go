package clientagent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

// handlers runs the agent's checks: one per request from Gryphon, each
// bounded by its deadline and by the cap on checks in flight.
type handlers struct {
	cfg     Config
	log     *slog.Logger
	docker  *dockerClient
	scripts *scriptRunner
	files   *fileWatcher
	net     *netProbe
	// slots bounds the checks in flight; see Config.MaxConcurrent.
	slots chan struct{}
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

// testResponse is the answer to a test: the agent is here, this is its build,
// and these are the checks it runs.
func (app *handlers) testResponse() agent.Response {
	return agent.Response{
		Action:      "test",
		OK:          true,
		Status:      "Success",
		DateTime:    time.Now(),
		NewStatusID: agent.StatusHealthy,
		Version:     version.Version(),
		Checks:      app.checkNames(),
	}
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
		// A panic here is on a goroutine of its own, where nothing above
		// could recover it: it would end the agent, and every check with it.
		defer func() {
			if rec := recover(); rec != nil {
				done <- result{
					statusID: agent.StatusUnknown,
					msg:      fmt.Sprintf("the %s check failed unexpectedly: %v", action, rec),
				}
			}
		}()
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

// run runs the check named action and answers for it, with the code the
// answer goes back with: 200, or 404 for a check this build does not know.
// Whatever carries the request -- an HTTP post, or a frame on the connection
// to Gryphon -- the check is run, bounded and answered here.
func (app *handlers) run(ctx context.Context, action, params string) (int, agent.Response) {
	fn, ok := app.lookup(action)
	if !ok {
		// Named as such, with the build and what it does run, so the server
		// can say "update the agent" rather than "404".
		return http.StatusNotFound, agent.Response{
			Action: action, OK: false, Status: agent.UnknownCheckStatus, DateTime: time.Now(),
			Version: version.Version(), Checks: app.checkNames(),
		}
	}

	// A slot, or "busy": past the cap the agent says so rather than starting
	// one more check on a host that is already struggling. The slot is held
	// until the check itself returns, deadline or not, so a pile of stuck
	// checks fills the cap instead of the process.
	select {
	case app.slots <- struct{}{}:
	default:
		return http.StatusOK, agent.Response{
			Action: action, OK: false, DateTime: time.Now(), NewStatusID: agent.StatusUnknown,
			Status:  fmt.Sprintf("the agent is busy: %d checks are already running", app.cfg.MaxConcurrent),
			Version: version.Version(),
		}
	}
	res := runWithDeadline(ctx, action, params, fn, func() { <-app.slots })

	return http.StatusOK, agent.Response{
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
	}
}
