package clientagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

// The Docker checks: what a node agent can see of the containers on it, and
// what a Swarm manager can see of the whole service.
//
// They fill the gap the system checks leave. Those read the node -- /proc is
// not namespaced, so memory and CPU are the machine's however they are asked --
// and a container OOM-killed at its 512Mi limit is invisible to a memory check
// on a 64GB node. Here the numbers come from the container's own cgroup by way
// of the Engine, and are judged against the limit the container was given.
//
// Two are verdicts and two are sensors, on the same rule as the other checks:
//
//   - swarm-service and container say healthy, warning or problem themselves,
//     because "two of three replicas" has one meaning and needs no threshold
//   - container-memory and container-cpu report a percentage of the
//     container's limit and leave the grading to Gryphon's thresholds
//
// A Swarm service is a question for a manager. The check says so when it is
// asked of a worker, rather than reporting a service outage nobody has.

// checkSwarmService reports how many of a service's tasks are running against
// how many should be.
func (d *dockerClient) checkSwarmService(ctx context.Context, params string) result {
	name, err := nameParam(params, agent.ParamService, "service")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	svc, ok, err := d.service(ctx, name)
	if err != nil {
		var derr *dockerError
		if asDockerError(err, &derr) && derr.notManager() {
			return result{statusID: agent.StatusUnknown,
				msg: phrase.T("this node is not a Swarm manager, so it cannot see service {name}; attach this check to a manager node", "name", name)}
		}
		return unknownResult(err)
	}
	if !ok {
		return result{statusID: agent.StatusProblem, msg: phrase.T("no service named {name} in this swarm", "name", name)}
	}

	running, desired, err := d.taskCounts(ctx, svc)
	if err != nil {
		return unknownResult(err)
	}

	msg := phrase.T("{name}: {n} of {desired} replicas running", "name", name, "n", running, "desired", desired)
	if svc.Spec.Mode.Global != nil {
		msg = phrase.T("{name}: {n} of {desired} nodes running", "name", name, "n", running, "desired", desired)
	}
	data := fmt.Sprintf("%d|%d", running, desired)

	status := agent.StatusHealthy
	switch {
	case desired == 0:
		status, msg = agent.StatusWarning, phrase.T("{name}: scaled to 0", "name", name)
	case running == 0:
		status = agent.StatusProblem
	case running < desired:
		status = agent.StatusWarning
	}

	// A paused update is a rollout that stopped because a task failed; every
	// replica may still be up on the old version, which is worth a warning
	// rather than a green light. It raises the verdict and never lowers it: a
	// service with nothing running is a problem whatever its update is doing.
	if u := svc.UpdateStatus; u != nil && strings.HasSuffix(u.State, "paused") {
		if status != agent.StatusProblem {
			status = agent.StatusWarning
		}
		msg = updatePaused(msg, u.State, strings.TrimSpace(u.Message))
	}
	return result{statusID: status, msg: msg, data: data}
}

// updatePaused is msg with the paused update said after it, in Docker's
// words for why.
func updatePaused(msg, state, why string) string {
	switch state {
	case "paused":
		return phrase.T("{msg} (update paused: {why})", "msg", msg, "why", why)
	case "rollback_paused":
		return phrase.T("{msg} (update rollback_paused: {why})", "msg", msg, "why", why)
	}
	return phrase.T("{msg} (update {state}: {why})", "msg", msg, "state", state, "why", why)
}

// checkSwarmStack reports how many of a stack's services have every task
// running. One check for the whole of a docker stack deploy, where the
// service check is one per service: a stack of thirty services is one row
// here, and the message names the services that are short.
func (d *dockerClient) checkSwarmStack(ctx context.Context, params string) result {
	name, err := nameParam(params, agent.ParamStack, "stack")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	services, err := d.stack(ctx, name)
	if err != nil {
		var derr *dockerError
		if asDockerError(err, &derr) && derr.notManager() {
			return result{statusID: agent.StatusUnknown,
				msg: phrase.T("this node is not a Swarm manager, so it cannot see stack {name}; attach this check to a manager node", "name", name)}
		}
		return unknownResult(err)
	}
	if len(services) == 0 {
		return result{statusID: agent.StatusProblem, msg: phrase.T("no stack named {name} in this swarm", "name", name)}
	}

	// Sorted so the message reads the same from one run to the next, and so
	// a diff between two runs is a real change.
	sort.Slice(services, func(i, j int) bool { return services[i].Spec.Name < services[j].Spec.Name })

	var whole, anyRunning int
	var short []string
	for _, svc := range services {
		running, desired, err := d.taskCounts(ctx, svc)
		if err != nil {
			return unknownResult(err)
		}
		if running > 0 {
			anyRunning++
		}
		if desired > 0 && running == desired {
			whole++
			continue
		}
		// The service's own name less the stack prefix, which every one of
		// them shares.
		short = append(short, fmt.Sprintf("%s %d/%d",
			strings.TrimPrefix(svc.Spec.Name, name+"_"), running, desired))
	}

	msg := phrase.T("{name}: {n} of {total} services fully running", "name", name, "n", whole, "total", len(services))
	data := fmt.Sprintf("%d|%d", whole, len(services))
	// Enough to act on; the service check on each is where the detail is.
	switch {
	case len(short) > 8:
		msg = phrase.T("{name}: {n} of {total} services fully running ({short}, and {more} more)",
			"name", name, "n", whole, "total", len(services), "short", strings.Join(short[:8], ", "), "more", len(short)-8)
	case len(short) > 0:
		msg = phrase.T("{name}: {n} of {total} services fully running ({short})",
			"name", name, "n", whole, "total", len(services), "short", strings.Join(short, ", "))
	}

	switch {
	case whole == len(services):
		return result{statusID: agent.StatusHealthy, msg: msg, data: data}
	case anyRunning == 0:
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	}
	return result{statusID: agent.StatusWarning, msg: msg, data: data}
}

// checkContainer reports whether a container on this node is up: running, and
// healthy if it has a healthcheck to say so.
func (d *dockerClient) checkContainer(ctx context.Context, params string) result {
	name, err := nameParam(params, agent.ParamContainer, "container")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	c, err := d.inspectContainer(ctx, name)
	if err != nil {
		var derr *dockerError
		if asDockerError(err, &derr) && derr.notFound() {
			return result{statusID: agent.StatusProblem, msg: phrase.T("no container named {name} on this node", "name", name)}
		}
		return unknownResult(err)
	}

	// Each state is a sentence of its own, with or without the uptime and
	// the reason: a sentence per combination is what lets a reader's
	// language have each one (pkg/phrase). The restarts and an out-of-memory
	// kill come after the sentence (withNotes), or before the reason when
	// there is one, which is where the agent has always put them.
	st := c.State
	notes := containerNotes(c)
	switch st.Status {
	case "running":
		started, err := time.Parse(time.RFC3339Nano, st.StartedAt)
		hasUp := err == nil
		up := ""
		if hasUp {
			up = humanDuration(time.Since(started))
		}
		if h := st.Health; h != nil {
			switch h.Status {
			case "healthy":
				msg := phrase.T("{name}: running, healthcheck passing", "name", name)
				if hasUp {
					msg = phrase.T("{name}: running for {up}, healthcheck passing", "name", name, "up", up)
				}
				return result{statusID: agent.StatusHealthy, data: h.Status, msg: withNotes(msg, c)}
			case "starting":
				msg := phrase.T("{name}: running, healthcheck still starting", "name", name)
				if hasUp {
					msg = phrase.T("{name}: running for {up}, healthcheck still starting", "name", name, "up", up)
				}
				return result{statusID: agent.StatusWarning, data: h.Status, msg: withNotes(msg, c)}
			default:
				why := ""
				if n := len(h.Log); n > 0 {
					why = firstLine(h.Log[n-1].Output)
				}
				var msg string
				switch {
				case hasUp && why != "" && notes != "":
					return result{statusID: agent.StatusProblem, data: h.Status,
						msg: phrase.T("{name}: running for {up} but its healthcheck has failed {n} times in a row, {notes}: {why}",
							"name", name, "up", up, "n", h.FailingStreak, "notes", notes, "why", why)}
				case why != "" && notes != "":
					return result{statusID: agent.StatusProblem, data: h.Status,
						msg: phrase.T("{name}: running but its healthcheck has failed {n} times in a row, {notes}: {why}",
							"name", name, "n", h.FailingStreak, "notes", notes, "why", why)}
				case hasUp && why != "":
					msg = phrase.T("{name}: running for {up} but its healthcheck has failed {n} times in a row: {why}",
						"name", name, "up", up, "n", h.FailingStreak, "why", why)
				case hasUp:
					msg = phrase.T("{name}: running for {up} but its healthcheck has failed {n} times in a row",
						"name", name, "up", up, "n", h.FailingStreak)
				case why != "":
					msg = phrase.T("{name}: running but its healthcheck has failed {n} times in a row: {why}",
						"name", name, "n", h.FailingStreak, "why", why)
				default:
					msg = phrase.T("{name}: running but its healthcheck has failed {n} times in a row",
						"name", name, "n", h.FailingStreak)
				}
				return result{statusID: agent.StatusProblem, data: h.Status, msg: withNotes(msg, c)}
			}
		}
		msg := phrase.T("{name}: running", "name", name)
		if hasUp {
			msg = phrase.T("{name}: running for {up}", "name", name, "up", up)
		}
		return result{statusID: agent.StatusHealthy, data: st.Status, msg: withNotes(msg, c)}

	case "paused":
		return result{statusID: agent.StatusWarning, data: st.Status,
			msg: withNotes(phrase.T("{name}: paused", "name", name), c)}

	case "restarting":
		return result{statusID: agent.StatusProblem, data: st.Status,
			msg: withNotes(phrase.T("{name}: restarting after exit code {code}", "name", name, "code", st.ExitCode), c)}

	case "created":
		return result{statusID: agent.StatusProblem, data: st.Status,
			msg: withNotes(phrase.T("{name}: created but never started", "name", name), c)}
	}

	// exited, dead, removing: exited, by far the usual one, in words of its
	// own, and the others in Docker's.
	why := firstLine(st.Error)
	var msg string
	switch {
	case st.Status == "exited" && why != "" && notes != "":
		return result{statusID: agent.StatusProblem, data: st.Status,
			msg: phrase.T("{name}: exited with code {code}, {notes}: {why}", "name", name, "code", st.ExitCode, "notes", notes, "why", why)}
	case why != "" && notes != "":
		return result{statusID: agent.StatusProblem, data: st.Status,
			msg: phrase.T("{name}: {state} with code {code}, {notes}: {why}",
				"name", name, "state", st.Status, "code", st.ExitCode, "notes", notes, "why", why)}
	case st.Status == "exited" && why != "":
		msg = phrase.T("{name}: exited with code {code}: {why}", "name", name, "code", st.ExitCode, "why", why)
	case st.Status == "exited":
		msg = phrase.T("{name}: exited with code {code}", "name", name, "code", st.ExitCode)
	case why != "":
		msg = phrase.T("{name}: {state} with code {code}: {why}", "name", name, "state", st.Status, "code", st.ExitCode, "why", why)
	default:
		msg = phrase.T("{name}: {state} with code {code}", "name", name, "state", st.Status, "code", st.ExitCode)
	}
	return result{statusID: agent.StatusProblem, data: st.Status, msg: withNotes(msg, c)}
}

// containerNotes is what else is worth knowing about a container -- that it
// has been restarted, and that it was killed for its memory -- for a message
// that says it before a reason, or "".
func containerNotes(c containerInspect) string {
	switch {
	case c.RestartCount > 0 && c.State.OOMKilled:
		return phrase.T("restarted {n} times, killed for exceeding its memory limit", "n", c.RestartCount)
	case c.RestartCount > 0:
		return phrase.T("restarted {n} times", "n", c.RestartCount)
	case c.State.OOMKilled:
		return phrase.T("killed for exceeding its memory limit")
	}
	return ""
}

// withNotes is a container's message with what else is worth knowing said
// after it: that it has been restarted, and that it was killed for its
// memory. Each is a format around the message, so the message itself is
// still recognised whichever of them follow it.
func withNotes(msg string, c containerInspect) string {
	if c.RestartCount > 0 {
		msg = phrase.T("{msg}, restarted {n} times", "msg", msg, "n", c.RestartCount)
	}
	if c.State.OOMKilled {
		msg = phrase.T("{msg}, killed for exceeding its memory limit", "msg", msg)
	}
	return msg
}

// checkContainerMemory measures a container's memory as a percentage of its
// limit. Without a limit the ceiling is the node's memory, and the message
// says so, because a threshold against that is a different thing.
func (d *dockerClient) checkContainerMemory(ctx context.Context, params string) result {
	name, err := nameParam(params, agent.ParamContainer, "container")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	c, err := d.inspectContainer(ctx, name)
	if err != nil {
		return d.cannotMeasure(name, err)
	}
	if !c.State.Running {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("{name} is not running ({state})", "name", name, "state", c.State.Status)}
	}

	s, err := d.stats(ctx, name, true)
	if err != nil {
		return d.cannotMeasure(name, err)
	}
	m := s.MemoryStats
	if m.Limit == 0 {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("Docker reported no memory figures for {name}", "name", name)}
	}

	// The page cache is reclaimable and does not count against the limit for
	// OOM purposes; docker stats leaves it out, and so does this, on whichever
	// of the two names the cgroup version uses.
	used := m.Usage
	cache := m.Stats.InactiveFile
	if cache == 0 {
		cache = m.Stats.TotalInactiveFile
	}
	if cache < used {
		used -= cache
	}
	pct := float64(used) / float64(m.Limit) * 100

	msg := phrase.T("{name}: {pct} used, {used} of its {limit} limit",
		"name", name, "pct", percent(pct), "used", humanBytes(used), "limit", humanBytes(m.Limit))
	if c.HostConfig.Memory == 0 {
		msg = phrase.T("{name}: {pct} used, {used} of the node's {limit} (no memory limit)",
			"name", name, "pct", percent(pct), "used", humanBytes(used), "limit", humanBytes(m.Limit))
	}
	return measured(pct, msg,
		fmt.Sprintf("%d|%d", used/1024, m.Limit/1024))
}

// checkContainerCPU measures a container's CPU as a percentage of its limit,
// or of the whole node when it has none.
func (d *dockerClient) checkContainerCPU(ctx context.Context, params string) result {
	name, err := nameParam(params, agent.ParamContainer, "container")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	c, err := d.inspectContainer(ctx, name)
	if err != nil {
		return d.cannotMeasure(name, err)
	}
	if !c.State.Running {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("{name} is not running ({state})", "name", name, "state", c.State.Status)}
	}

	// Two samples a second apart, taken by the Engine, so precpu_stats is
	// the earlier one.
	s, err := d.stats(ctx, name, false)
	if err != nil {
		return d.cannotMeasure(name, err)
	}
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemCPUUsage) - float64(s.PreCPUStats.SystemCPUUsage)
	if sysDelta <= 0 || cpuDelta < 0 {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("Docker reported no CPU sample for {name}", "name", name)}
	}
	cores := float64(s.CPUStats.OnlineCPUs)
	if cores == 0 {
		cores = float64(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if cores == 0 {
		cores = 1
	}
	// Share of the whole node, then in cores.
	share := cpuDelta / sysDelta
	usedCores := share * cores

	limit := containerCPULimit(c)
	if limit > 0 {
		pct := usedCores / limit * 100
		return measured(pct,
			phrase.T("{name}: {pct} of its {limit} CPU limit", "name", name, "pct", percent(pct), "limit", trimFloat(limit)),
			fmt.Sprintf("%d|%d", int64(usedCores*1000), int64(limit*1000)))
	}
	pct := share * 100
	return measured(pct,
		phrase.T("{name}: {pct} of the node's {cores} CPUs (no CPU limit)", "name", name, "pct", percent(pct), "cores", trimFloat(cores)),
		fmt.Sprintf("%d|%d", int64(usedCores*1000), int64(cores*1000)))
}

// containerCPULimit is the container's CPU limit in cores, or zero for none.
// Compose and Swarm set it as NanoCpus; a bare docker run --cpu-quota sets
// the quota and period instead.
func containerCPULimit(c containerInspect) float64 {
	if c.HostConfig.NanoCPUs > 0 {
		return float64(c.HostConfig.NanoCPUs) / 1e9
	}
	if c.HostConfig.CPUQuota > 0 && c.HostConfig.CPUPeriod > 0 {
		return float64(c.HostConfig.CPUQuota) / float64(c.HostConfig.CPUPeriod)
	}
	return 0
}

// cannotMeasure is unknownResult for the sensors, with the one case that is
// worth its own words: the container is not there, which a sensor cannot
// grade and the container check reports.
func (d *dockerClient) cannotMeasure(name string, err error) result {
	var derr *dockerError
	if asDockerError(err, &derr) && derr.notFound() {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("no container named {name} on this node", "name", name)}
	}
	return unknownResult(err)
}

func asDockerError(err error, target **dockerError) bool {
	e, ok := err.(*dockerError)
	if ok {
		*target = e
	}
	return ok
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func trimFloat(f float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
}

// humanDuration is a container's uptime in the units that matter at its scale.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
