package clientagent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

// The Kubernetes checks: what an agent running inside a cluster can read of
// it from the API server. They are the Swarm checks' counterparts, and grade
// the same way where the question is the same -- a workload short of
// replicas is a warning and one with none ready a problem, as a Swarm
// service is -- so a person running both reads one set of rules.
//
// All five are verdicts. "Two of three replicas ready" and "CrashLoopBackOff"
// have one meaning each and need no threshold from the server. The crash
// check's restart count is a setting rather than a threshold, because it
// decides which containers are named, not how bad a number is.
//
// Every one reads; none writes. What the agent may read is the RBAC the
// cluster's administrator applied, and a refusal says which Role is missing.

// kubeChecks are the checks that need the API server. They are offered only
// by an agent running inside a cluster; see newKubeClient.
var kubeChecks = map[string]func(*kubeClient, context.Context, string) result{
	"k8s-workload": (*kubeClient).checkWorkload,
	"k8s-app":      (*kubeClient).checkApp,
	"k8s-nodes":    (*kubeClient).checkNodes,
	"k8s-pods":     (*kubeClient).checkPods,
	"k8s-cronjob":  (*kubeClient).checkCronJob,
}

// kubeNow is the clock the CronJob check reads, a variable so a test can
// stand at a chosen moment in a schedule.
var kubeNow = time.Now

// kubeShortNames is how many names a message lists before "and N more", as
// the Swarm stack check does: enough to act on, and the detail is a kubectl
// away.
const kubeShortNames = 8

// workloadKind is one of the three kinds a workload check reads.
type workloadKind struct {
	// name is the kind as the check's setting and messages spell it.
	name string
	// resource is the plural the API path and a refusal name it by.
	resource string
	// unit is what its replicas are counted in.
	unit string
}

var workloadKinds = map[string]workloadKind{
	agent.KindDeployment:  {agent.KindDeployment, "deployments", "replicas"},
	agent.KindStatefulSet: {agent.KindStatefulSet, "statefulsets", "replicas"},
	agent.KindDaemonSet:   {agent.KindDaemonSet, "daemonsets", "nodes"},
}

// workloadState is what the checks need of any of the three kinds.
type workloadState struct {
	name           string
	ready, desired int32
	// stuck is whether a rollout has stopped, and stuckWhy the controller's
	// words for why, when it gave any.
	stuck    bool
	stuckWhy string
	// paused is a rollout paused by hand, which is worth saying.
	paused bool
}

func deploymentState(d kubeDeployment) workloadState {
	w := workloadState{name: d.Metadata.Name, ready: d.Status.ReadyReplicas, desired: 1}
	if d.Spec.Replicas != nil {
		w.desired = *d.Spec.Replicas
	}
	for _, c := range d.Status.Conditions {
		// The controller gives up on a rollout after
		// progressDeadlineSeconds (ten minutes unless set) and says so here;
		// the old replicas may well still be serving.
		if c.Type == "Progressing" && c.Status == "False" && c.Reason == "ProgressDeadlineExceeded" {
			w.stuck, w.stuckWhy = true, firstLine(c.Message)
		}
	}
	w.paused = d.Spec.Paused
	return w
}

func statefulSetState(s kubeStatefulSet) workloadState {
	w := workloadState{name: s.Metadata.Name, ready: s.Status.ReadyReplicas, desired: 1}
	if s.Spec.Replicas != nil {
		w.desired = *s.Spec.Replicas
	}
	return w
}

func daemonSetState(d kubeDaemonSet) workloadState {
	return workloadState{name: d.Metadata.Name, ready: d.Status.NumberReady, desired: d.Status.DesiredNumberScheduled}
}

// workloadPath is the API path of one workload, or of all of a kind in a
// namespace when name is empty.
func workloadPath(kind workloadKind, namespace, name string) string {
	p := "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/" + kind.resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

// readWorkload fetches one workload of kind.
func (k *kubeClient) readWorkload(ctx context.Context, kind workloadKind, namespace, name string) (workloadState, error) {
	path := workloadPath(kind, namespace, name)
	switch kind.name {
	case "deployment":
		var d kubeDeployment
		err := k.request(ctx, "get", kind.resource, namespace, path, nil, &d)
		return deploymentState(d), err
	case "statefulset":
		var s kubeStatefulSet
		err := k.request(ctx, "get", kind.resource, namespace, path, nil, &s)
		return statefulSetState(s), err
	default:
		var d kubeDaemonSet
		err := k.request(ctx, "get", kind.resource, namespace, path, nil, &d)
		return daemonSetState(d), err
	}
}

// checkWorkload reports how many of a Deployment's, StatefulSet's or
// DaemonSet's pods are ready against how many should be.
func (k *kubeClient) checkWorkload(ctx context.Context, params string) result {
	p, err := readKubeParams(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	ns, err := p.namespace()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	kindName := strings.ToLower(strings.TrimSpace(p.values.Get(agent.ParamKind)))
	if kindName == "" {
		kindName = "deployment"
	}
	kind, ok := workloadKinds[kindName]
	if !ok {
		return result{statusID: agent.StatusUnknown,
			msg: phrase.T("{kind} is not a kind this check reads: deployment, statefulset or daemonset", "kind", strconv.Quote(kindName))}
	}
	name, err := p.name(kind.name)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	w, err := k.readWorkload(ctx, kind, ns, name)
	if err != nil {
		var kerr *kubeError
		if asKubeError(err, &kerr) && kerr.notFound() {
			return result{statusID: agent.StatusProblem,
				msg: phrase.T("no {kind} named {name} in namespace {namespace}", "kind", kind.name, "name", name, "namespace", ns)}
		}
		return kubeUnknown(err)
	}

	msg := phrase.T("{name}: {ready} of {desired} replicas ready", "name", name, "ready", w.ready, "desired", w.desired)
	if kind.unit == "nodes" {
		msg = phrase.T("{name}: {ready} of {desired} nodes ready", "name", name, "ready", w.ready, "desired", w.desired)
	}
	data := fmt.Sprintf("%d|%d", w.ready, w.desired)

	status := agent.StatusHealthy
	switch {
	case w.desired == 0:
		status, msg = agent.StatusWarning, phrase.T("{name}: scaled to 0", "name", name)
	case w.ready == 0:
		status = agent.StatusProblem
	case w.ready < w.desired:
		status = agent.StatusWarning
	}
	// A stuck rollout raises the verdict to a warning and never lowers it,
	// as a paused Swarm update does: the old replicas may all be serving.
	if w.stuck && status != agent.StatusProblem {
		status = agent.StatusWarning
	}
	switch {
	case w.stuck && w.stuckWhy != "":
		msg = phrase.T("{msg} (rollout stuck: {why})", "msg", msg, "why", w.stuckWhy)
	case w.stuck:
		msg = phrase.T("{msg} (rollout stuck)", "msg", msg)
	case w.paused:
		msg = phrase.T("{msg} (rollout paused)", "msg", msg)
	}
	return result{statusID: status, msg: msg, data: data}
}

// checkApp reports how many of the workloads in a namespace, or matching a
// selector there, have every pod ready: the Swarm stack check's counterpart,
// one row for an application however many workloads make it up.
func (k *kubeClient) checkApp(ctx context.Context, params string) result {
	p, err := readKubeParams(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	ns, err := p.namespace()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	sel, err := p.selector()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	type named struct {
		kind string
		workloadState
	}
	var all []named
	deps, err := list[kubeDeployment](ctx, k, "deployments", ns, workloadPath(workloadKinds["deployment"], ns, ""), sel)
	if err != nil {
		return kubeUnknown(err)
	}
	for _, d := range deps {
		all = append(all, named{"deployment", deploymentState(d)})
	}
	sets, err := list[kubeStatefulSet](ctx, k, "statefulsets", ns, workloadPath(workloadKinds["statefulset"], ns, ""), sel)
	if err != nil {
		return kubeUnknown(err)
	}
	for _, s := range sets {
		all = append(all, named{"statefulset", statefulSetState(s)})
	}
	daemons, err := list[kubeDaemonSet](ctx, k, "daemonsets", ns, workloadPath(workloadKinds["daemonset"], ns, ""), sel)
	if err != nil {
		return kubeUnknown(err)
	}
	for _, d := range daemons {
		all = append(all, named{"daemonset", daemonSetState(d)})
	}

	// Nothing matched is a problem rather than a clean bill of health, so
	// that a mistyped selector does not read as an application that is up.
	if len(all) == 0 {
		msg := phrase.T("no deployments, statefulsets or daemonsets match namespace {namespace}", "namespace", ns)
		if sel != "" {
			msg = phrase.T("no deployments, statefulsets or daemonsets match {selector} in {namespace}", "selector", sel, "namespace", ns)
		}
		return result{statusID: agent.StatusProblem, msg: msg}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].kind != all[j].kind {
			return all[i].kind < all[j].kind
		}
		return all[i].name < all[j].name
	})

	var whole, anyReady int
	var short, stuck []string
	for _, w := range all {
		if w.ready > 0 {
			anyReady++
		}
		if w.stuck {
			stuck = append(stuck, w.kind+"/"+w.name)
		}
		if w.desired > 0 && w.ready == w.desired {
			whole++
			continue
		}
		short = append(short, fmt.Sprintf("%s/%s %d/%d", w.kind, w.name, w.ready, w.desired))
	}

	var msg string
	switch {
	case sel == "" && len(short) == 0:
		msg = phrase.T("namespace {namespace}: {n} of {total} workloads fully ready",
			"namespace", ns, "n", whole, "total", len(all))
	case sel == "":
		msg = phrase.T("namespace {namespace}: {n} of {total} workloads fully ready ({short})",
			"namespace", ns, "n", whole, "total", len(all), "short", capNames(short))
	case len(short) == 0:
		msg = phrase.T("{selector} in {namespace}: {n} of {total} workloads fully ready",
			"selector", sel, "namespace", ns, "n", whole, "total", len(all))
	default:
		msg = phrase.T("{selector} in {namespace}: {n} of {total} workloads fully ready ({short})",
			"selector", sel, "namespace", ns, "n", whole, "total", len(all), "short", capNames(short))
	}
	data := fmt.Sprintf("%d|%d", whole, len(all))
	if len(stuck) > 0 {
		msg = phrase.T("{msg}; rollout stuck: {names}", "msg", msg, "names", capNames(stuck))
	}

	switch {
	case anyReady == 0:
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	case whole == len(all) && len(stuck) == 0:
		return result{statusID: agent.StatusHealthy, msg: msg, data: data}
	}
	return result{statusID: agent.StatusWarning, msg: msg, data: data}
}

// nodePressures are the node conditions that are bad news when True. Ready
// is the other way round and is read separately.
var nodePressures = []string{"MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"}

// checkNodes reports how many of the cluster's nodes, or those matching a
// selector, are Ready, and names the ones that are not or are under pressure.
//
// One node not Ready is a warning, as one Swarm replica short is: a cluster
// is built to lose a node, and a node joining from an autoscaler is NotReady
// for its first minute. None Ready is a problem.
func (k *kubeClient) checkNodes(ctx context.Context, params string) result {
	p, err := readKubeParams(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	sel, err := p.selector()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	nodes, err := list[kubeNode](ctx, k, "nodes", "", "/api/v1/nodes", sel)
	if err != nil {
		return kubeUnknown(err)
	}
	if len(nodes) == 0 {
		if sel != "" {
			return result{statusID: agent.StatusProblem, msg: phrase.T("no nodes matching {selector}", "selector", sel)}
		}
		return result{statusID: agent.StatusProblem, msg: phrase.T("no nodes")}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Metadata.Name < nodes[j].Metadata.Name })

	var ready int
	var notReady, pressured, cordoned []string
	for _, n := range nodes {
		isReady := false
		var pressures []string
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" {
				isReady = c.Status == "True"
				continue
			}
			for _, pr := range nodePressures {
				if c.Type == pr && c.Status == "True" {
					pressures = append(pressures, pr)
				}
			}
		}
		if isReady {
			ready++
		} else {
			notReady = append(notReady, n.Metadata.Name)
		}
		if len(pressures) > 0 {
			pressured = append(pressured, n.Metadata.Name+" "+strings.Join(pressures, "+"))
		}
		// Cordoned is said, not graded: draining a node for maintenance
		// is ordinary.
		if n.Spec.Unschedulable {
			cordoned = append(cordoned, n.Metadata.Name)
		}
	}

	msg := phrase.T("{ready} of {total} nodes ready", "ready", ready, "total", len(nodes))
	if sel != "" {
		msg = phrase.T("{ready} of {total} nodes matching {selector} ready", "ready", ready, "total", len(nodes), "selector", sel)
	}
	data := fmt.Sprintf("%d|%d", ready, len(nodes))
	msg = nodeNotes(msg, notReady, pressured, cordoned)

	switch {
	case ready == 0:
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	case len(notReady) > 0 || len(pressured) > 0:
		return result{statusID: agent.StatusWarning, msg: msg, data: data}
	}
	return result{statusID: agent.StatusHealthy, msg: msg, data: data}
}

// nodeNotes is the nodes check's message with the nodes worth naming said
// after it: a sentence for each combination, so that each is translated
// whole.
func nodeNotes(msg string, notReady, pressured, cordoned []string) string {
	n, p, c := capNames(notReady), capNames(pressured), capNames(cordoned)
	switch {
	case n != "" && p != "" && c != "":
		return phrase.T("{msg} (not ready: {notready}; under pressure: {pressured}; cordoned: {cordoned})",
			"msg", msg, "notready", n, "pressured", p, "cordoned", c)
	case n != "" && p != "":
		return phrase.T("{msg} (not ready: {notready}; under pressure: {pressured})", "msg", msg, "notready", n, "pressured", p)
	case n != "" && c != "":
		return phrase.T("{msg} (not ready: {notready}; cordoned: {cordoned})", "msg", msg, "notready", n, "cordoned", c)
	case p != "" && c != "":
		return phrase.T("{msg} (under pressure: {pressured}; cordoned: {cordoned})", "msg", msg, "pressured", p, "cordoned", c)
	case n != "":
		return phrase.T("{msg} (not ready: {notready})", "msg", msg, "notready", n)
	case p != "":
		return phrase.T("{msg} (under pressure: {pressured})", "msg", msg, "pressured", p)
	case c != "":
		return phrase.T("{msg} (cordoned: {cordoned})", "msg", msg, "cordoned", c)
	}
	return msg
}

// stuckReasons are the waiting reasons that mean a container will not come
// up without somebody doing something: a crash it keeps repeating, an image
// it cannot pull, a configuration it cannot be created from.
var stuckReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"InvalidImageName":           true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
}

// The crash check's defaults: more than five restarts, the last of them in
// the past hour.
const (
	defaultRestarts      = 5
	defaultWindowMinutes = 60
)

// checkPods reports pods in a namespace whose containers are stuck --
// crash-looping, or unable to pull or start -- and, as a warning, those that
// restart often enough to be worth a look.
//
// Restarts are counted only when the last of them is recent: a pod that
// restarted twelve times last month and has run cleanly since is fine, and
// restartCount never goes down.
func (k *kubeClient) checkPods(ctx context.Context, params string) result {
	p, err := readKubeParams(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	ns, err := p.namespace()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	sel, err := p.selector()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	threshold, err := p.count(agent.ParamRestarts, "restarts", defaultRestarts)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	windowMinutes, err := p.count(agent.ParamWindow, "minutes", defaultWindowMinutes)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	window := time.Duration(windowMinutes) * time.Minute

	pods, err := list[kubePod](ctx, k, "pods", ns, "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods", sel)
	if err != nil {
		return kubeUnknown(err)
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Metadata.Name < pods[j].Metadata.Name })

	now := kubeNow()
	var live int
	var stuck, restarting []string
	for _, pod := range pods {
		// A Job's finished pods, and pods evicted or otherwise done with,
		// are history rather than something crashing now. The CronJob
		// check is where a failed run is reported.
		if pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			continue
		}
		live++
		statuses := append(append([]kubeContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
		for _, cs := range statuses {
			who := pod.Metadata.Name + "/" + cs.Name
			if w := cs.State.Waiting; w != nil && stuckReasons[w.Reason] {
				stuck = append(stuck, fmt.Sprintf("%s %s (%d restarts)", who, w.Reason, cs.RestartCount))
				continue
			}
			// Between two attempts a crash-looping container is not
			// waiting but terminated, and early on, while the back-off is
			// short, that is much of the time. One that failed and has
			// already been restarted is crashing whichever state it was
			// caught in.
			if t := cs.State.Terminated; t != nil && t.ExitCode != 0 && cs.RestartCount > 0 {
				stuck = append(stuck, fmt.Sprintf("%s exited %d, %s (%d restarts)", who, t.ExitCode, t.Reason, cs.RestartCount))
				continue
			}
			last := cs.LastState.Terminated
			if cs.RestartCount > threshold && last != nil && now.Sub(last.FinishedAt) <= window {
				restarting = append(restarting, fmt.Sprintf("%s %d restarts, last %s ago", who, cs.RestartCount, humanDuration(now.Sub(last.FinishedAt))))
			}
		}
	}

	data := fmt.Sprintf("%d|%d", len(stuck), live)
	// Each sentence twice: for a namespace, and for a selector in one.
	bySelector := sel != ""
	switch {
	case live == 0:
		// Healthy, and saying why: a namespace of CronJobs has no pods
		// between runs. Whether anything is meant to be running is the
		// workload and app checks' question.
		msg := phrase.T("no running pods match namespace {namespace}, so none is crash-looping", "namespace", ns)
		if bySelector {
			msg = phrase.T("no running pods match {selector} in {namespace}, so none is crash-looping", "selector", sel, "namespace", ns)
		}
		return result{statusID: agent.StatusHealthy, data: data, msg: msg}
	case len(stuck) > 0:
		msg := phrase.T("namespace {namespace}: {n} of {live} pods have a container that will not start: {stuck}",
			"namespace", ns, "n", len(stuck), "live", live, "stuck", capNames(stuck))
		if bySelector {
			msg = phrase.T("{selector} in {namespace}: {n} of {live} pods have a container that will not start: {stuck}",
				"selector", sel, "namespace", ns, "n", len(stuck), "live", live, "stuck", capNames(stuck))
		}
		if len(restarting) > 0 {
			msg = phrase.T("{msg}; restarting often: {names}", "msg", msg, "names", capNames(restarting))
		}
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	case len(restarting) > 0:
		var msg string
		switch {
		case live == 1 && bySelector:
			msg = phrase.T("{selector} in {namespace}: 1 pod, restarting often: {names}",
				"selector", sel, "namespace", ns, "names", capNames(restarting))
		case live == 1:
			msg = phrase.T("namespace {namespace}: 1 pod, restarting often: {names}",
				"namespace", ns, "names", capNames(restarting))
		case bySelector:
			msg = phrase.T("{selector} in {namespace}: {live} pods, restarting often: {names}",
				"selector", sel, "namespace", ns, "live", live, "names", capNames(restarting))
		default:
			msg = phrase.T("namespace {namespace}: {live} pods, restarting often: {names}",
				"namespace", ns, "live", live, "names", capNames(restarting))
		}
		return result{statusID: agent.StatusWarning, data: data, msg: msg}
	}
	var msg string
	switch {
	case live == 1 && bySelector:
		msg = phrase.T("{selector} in {namespace}: 1 pod, not crash-looping", "selector", sel, "namespace", ns)
	case live == 1:
		msg = phrase.T("namespace {namespace}: 1 pod, not crash-looping", "namespace", ns)
	case bySelector:
		msg = phrase.T("{selector} in {namespace}: {live} pods, none crash-looping", "selector", sel, "namespace", ns, "live", live)
	default:
		msg = phrase.T("namespace {namespace}: {live} pods, none crash-looping", "namespace", ns, "live", live)
	}
	return result{statusID: agent.StatusHealthy, data: data, msg: msg}
}

// cronGrace is how long after its scheduled time a run may take to show up
// as active before it counts as missed: the controller creates the Job within
// seconds, and the pod takes a little longer.
const cronGrace = 2 * time.Minute

// cronMaxMissed is as far as the CronJob check counts missed runs. Past two
// the verdict does not change, and a job every minute that has not succeeded
// in a month would otherwise mean forty thousand steps through its schedule.
const cronMaxMissed = 3

// checkCronJob reports whether a CronJob has succeeded as often as its
// schedule says it should.
//
// It counts the scheduled times since the last success (or since the CronJob
// was created, when it never has) that are more than cronGrace in the past.
// None is healthy. One is a warning: that run failed, or never started. Two or
// more is a problem. A run still active counts for one less, so a job that
// takes an hour is not late while it runs.
//
// The schedule is read with robfig/cron's standard parser, which is the one
// the CronJob controller itself uses, in the CronJob's own time zone.
func (k *kubeClient) checkCronJob(ctx context.Context, params string) result {
	p, err := readKubeParams(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	ns, err := p.namespace()
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	name, err := p.name("CronJob")
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}

	var cj kubeCronJob
	path := "/apis/batch/v1/namespaces/" + url.PathEscape(ns) + "/cronjobs/" + url.PathEscape(name)
	if err := k.request(ctx, "get", "cronjobs", ns, path, nil, &cj); err != nil {
		var kerr *kubeError
		if asKubeError(err, &kerr) && kerr.notFound() {
			return result{statusID: agent.StatusProblem,
				msg: phrase.T("no {kind} named {name} in namespace {namespace}", "kind", "CronJob", "name", name, "namespace", ns)}
		}
		return kubeUnknown(err)
	}

	if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
		return result{statusID: agent.StatusProblem, data: "suspended", msg: phrase.T("{name}: suspended, so it will not run", "name", name)}
	}

	spec := cj.Spec.Schedule
	loc := time.UTC
	if tz := cj.Spec.TimeZone; tz != nil && *tz != "" {
		l, err := time.LoadLocation(*tz)
		if err != nil {
			return result{statusID: agent.StatusUnknown,
				msg: phrase.T("{name}: cannot read its time zone {zone}: {err}", "name", name, "zone", strconv.Quote(*tz), "err", err)}
		}
		loc = l
		spec = "CRON_TZ=" + *tz + " " + spec
	}
	sched, err := cron.ParseStandard(spec)
	if err != nil {
		return result{statusID: agent.StatusUnknown,
			msg: phrase.T("{name}: cannot read its schedule {schedule}: {err}", "name", name, "schedule", strconv.Quote(cj.Spec.Schedule), "err", err)}
	}

	now := kubeNow()
	base := cj.Metadata.CreationTimestamp
	succeeded := cj.Status.LastSuccessfulTime != nil
	if succeeded {
		base = *cj.Status.LastSuccessfulTime
	}

	missed := 0
	due := sched.Next(base)
	first := due
	for !due.IsZero() && !due.After(now.Add(-cronGrace)) && missed < cronMaxMissed {
		missed++
		due = sched.Next(due)
	}
	active := len(cj.Status.Active) > 0
	late := missed
	if active && late > 0 {
		late--
	}
	data := fmt.Sprint(missed)

	at := func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04 MST") }
	ago := humanDuration(now.Sub(base))
	switch {
	case missed == 0 && !due.IsZero() && !due.After(now):
		// Due, and still inside cronGrace: the run has started, or failed
		// already, or not shown up yet, and is not late. It is not the next
		// run either; that would name a time already gone.
		var msg string
		switch {
		case active && succeeded:
			msg = phrase.T("{name}: last succeeded {ago} ago; the run due {at} is running", "name", name, "ago", ago, "at", at(due))
		case active:
			msg = phrase.T("{name}: the run due {at} is running", "name", name, "at", at(due))
		case succeeded:
			msg = phrase.T("{name}: last succeeded {ago} ago; the run due {at} has not succeeded yet", "name", name, "ago", ago, "at", at(due))
		default:
			msg = phrase.T("{name}: the run due {at} has not succeeded yet", "name", name, "at", at(due))
		}
		return result{statusID: agent.StatusHealthy, msg: msg, data: data}
	case missed == 0:
		msg := phrase.T("{name}: last succeeded {ago} ago", "name", name, "ago", ago)
		if !succeeded {
			msg = phrase.T("{name}: no run due yet", "name", name)
		}
		if !due.IsZero() {
			msg = phrase.T("{msg}; next run {at}", "msg", msg, "at", at(due))
		}
		if active {
			msg = phrase.T("{msg}; running now", "msg", msg)
		}
		return result{statusID: agent.StatusHealthy, msg: msg, data: data}
	case late == 0:
		return result{statusID: agent.StatusHealthy, data: data,
			msg: phrase.T("{name}: the run due {at} is running", "name", name, "at", at(first))}
	}

	var msg string
	switch {
	case missed == 1:
		msg = phrase.T("{name}: the run due {at} has not succeeded (it failed, or never started)", "name", name, "at", at(first))
	case missed >= cronMaxMissed && succeeded:
		msg = phrase.T("{name}: {n} or more scheduled runs have passed since the last success, {ago} ago without one succeeding (the first was due {at})",
			"name", name, "n", cronMaxMissed, "ago", ago, "at", at(first))
	case missed >= cronMaxMissed:
		msg = phrase.T("{name}: {n} or more scheduled runs have passed since it was created {ago} ago without one succeeding (the first was due {at})",
			"name", name, "n", cronMaxMissed, "ago", ago, "at", at(first))
	case succeeded:
		msg = phrase.T("{name}: {n} scheduled runs have passed since the last success, {ago} ago without one succeeding (the first was due {at})",
			"name", name, "n", missed, "ago", ago, "at", at(first))
	default:
		msg = phrase.T("{name}: {n} scheduled runs have passed since it was created {ago} ago without one succeeding (the first was due {at})",
			"name", name, "n", missed, "ago", ago, "at", at(first))
	}
	if active {
		msg = phrase.T("{msg}; one is running now", "msg", msg)
	}
	if late == 1 {
		return result{statusID: agent.StatusWarning, msg: msg, data: data}
	}
	return result{statusID: agent.StatusProblem, msg: msg, data: data}
}

// capNames joins names for a message, past kubeShortNames as "and N more".
func capNames(names []string) string {
	if len(names) > kubeShortNames {
		rest := len(names) - kubeShortNames
		names = append(names[:kubeShortNames:kubeShortNames], fmt.Sprintf("and %d more", rest))
	}
	return strings.Join(names, ", ")
}

// kubeUnknown is unknownResult for the Kubernetes checks. A refusal from the
// API server is said as it is -- which permission, where, and what to apply
// rather than as a measurement that failed.
func kubeUnknown(err error) result {
	var kerr *kubeError
	if asKubeError(err, &kerr) && (kerr.status == http.StatusUnauthorized || kerr.status == http.StatusForbidden) {
		return result{statusID: agent.StatusUnknown, msg: err.Error()}
	}
	return unknownResult(err)
}
