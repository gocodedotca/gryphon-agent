package clientagent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
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
	// stuck is why a rollout has stopped, empty when it has not.
	stuck string
	// note is anything else worth saying: a rollout paused by hand.
	note string
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
			w.stuck = "rollout stuck"
			if m := firstLine(c.Message); m != "" {
				w.stuck += ": " + m
			}
		}
	}
	if d.Spec.Paused {
		w.note = "rollout paused"
	}
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
			msg: fmt.Sprintf("%q is not a kind this check reads: deployment, statefulset or daemonset", kindName)}
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
				msg: fmt.Sprintf("no %s named %s in namespace %s", kind.name, name, ns)}
		}
		return kubeUnknown(err)
	}

	msg := fmt.Sprintf("%s: %d of %d %s ready", name, w.ready, w.desired, kind.unit)
	data := fmt.Sprintf("%d|%d", w.ready, w.desired)

	status := agent.StatusHealthy
	switch {
	case w.desired == 0:
		status, msg = agent.StatusWarning, name+": scaled to 0"
	case w.ready == 0:
		status = agent.StatusProblem
	case w.ready < w.desired:
		status = agent.StatusWarning
	}
	// A stuck rollout raises the verdict to a warning and never lowers it,
	// as a paused Swarm update does: the old replicas may all be serving.
	if w.stuck != "" {
		if status != agent.StatusProblem {
			status = agent.StatusWarning
		}
		msg += " (" + w.stuck + ")"
	} else if w.note != "" {
		msg += " (" + w.note + ")"
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

	scope := "namespace " + ns
	if sel != "" {
		scope = sel + " in " + ns
	}
	// Nothing matched is a problem rather than a clean bill of health, so
	// that a mistyped selector does not read as an application that is up.
	if len(all) == 0 {
		return result{statusID: agent.StatusProblem, msg: "no deployments, statefulsets or daemonsets match " + scope}
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
		if w.stuck != "" {
			stuck = append(stuck, w.kind+"/"+w.name)
		}
		if w.desired > 0 && w.ready == w.desired {
			whole++
			continue
		}
		short = append(short, fmt.Sprintf("%s/%s %d/%d", w.kind, w.name, w.ready, w.desired))
	}

	msg := fmt.Sprintf("%s: %d of %d workloads fully ready", scope, whole, len(all))
	data := fmt.Sprintf("%d|%d", whole, len(all))
	if len(short) > 0 {
		msg += " (" + capNames(short) + ")"
	}
	if len(stuck) > 0 {
		msg += "; rollout stuck: " + capNames(stuck)
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
	scope := "nodes"
	if sel != "" {
		scope = "nodes matching " + sel
	}
	if len(nodes) == 0 {
		return result{statusID: agent.StatusProblem, msg: "no " + scope}
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

	msg := fmt.Sprintf("%d of %d %s ready", ready, len(nodes), scope)
	data := fmt.Sprintf("%d|%d", ready, len(nodes))
	var notes []string
	if len(notReady) > 0 {
		notes = append(notes, "not ready: "+capNames(notReady))
	}
	if len(pressured) > 0 {
		notes = append(notes, "under pressure: "+capNames(pressured))
	}
	if len(cordoned) > 0 {
		notes = append(notes, "cordoned: "+capNames(cordoned))
	}
	if len(notes) > 0 {
		msg += " (" + strings.Join(notes, "; ") + ")"
	}

	switch {
	case ready == 0:
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	case len(notReady) > 0 || len(pressured) > 0:
		return result{statusID: agent.StatusWarning, msg: msg, data: data}
	}
	return result{statusID: agent.StatusHealthy, msg: msg, data: data}
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
	scope := "namespace " + ns
	if sel != "" {
		scope = sel + " in " + ns
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
	switch {
	case live == 0:
		// Healthy, and saying why: a namespace of CronJobs has no pods
		// between runs. Whether anything is meant to be running is the
		// workload and app checks' question.
		return result{statusID: agent.StatusHealthy, data: data,
			msg: "no running pods match " + scope + ", so none is crash-looping"}
	case len(stuck) > 0:
		msg := fmt.Sprintf("%s: %d of %d pods have a container that will not start: %s", scope, len(stuck), live, capNames(stuck))
		if len(restarting) > 0 {
			msg += "; restarting often: " + capNames(restarting)
		}
		return result{statusID: agent.StatusProblem, msg: msg, data: data}
	case len(restarting) > 0:
		return result{statusID: agent.StatusWarning, data: data,
			msg: fmt.Sprintf("%s: %d pods, restarting often: %s", scope, live, capNames(restarting))}
	}
	return result{statusID: agent.StatusHealthy, data: data,
		msg: fmt.Sprintf("%s: %d pods, none crash-looping", scope, live)}
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
			return result{statusID: agent.StatusProblem, msg: fmt.Sprintf("no CronJob named %s in namespace %s", name, ns)}
		}
		return kubeUnknown(err)
	}

	if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
		return result{statusID: agent.StatusProblem, data: "suspended", msg: name + ": suspended, so it will not run"}
	}

	spec := cj.Spec.Schedule
	loc := time.UTC
	if tz := cj.Spec.TimeZone; tz != nil && *tz != "" {
		l, err := time.LoadLocation(*tz)
		if err != nil {
			return result{statusID: agent.StatusUnknown,
				msg: fmt.Sprintf("%s: cannot read its time zone %q: %v", name, *tz, err)}
		}
		loc = l
		spec = "CRON_TZ=" + *tz + " " + spec
	}
	sched, err := cron.ParseStandard(spec)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: fmt.Sprintf("%s: cannot read its schedule %q: %v", name, cj.Spec.Schedule, err)}
	}

	now := kubeNow()
	base := cj.Metadata.CreationTimestamp
	since := "it was created " + humanDuration(now.Sub(base)) + " ago"
	if t := cj.Status.LastSuccessfulTime; t != nil {
		base = *t
		since = "the last success, " + humanDuration(now.Sub(base)) + " ago"
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
	switch {
	case missed == 0:
		msg := name + ": last succeeded " + humanDuration(now.Sub(base)) + " ago"
		if cj.Status.LastSuccessfulTime == nil {
			msg = name + ": no run due yet"
		}
		if !due.IsZero() {
			msg += "; next run " + at(due)
		}
		if active {
			msg += "; running now"
		}
		return result{statusID: agent.StatusHealthy, msg: msg, data: data}
	case late == 0:
		return result{statusID: agent.StatusHealthy, data: data,
			msg: name + ": the run due " + at(first) + " is running"}
	}

	runs := fmt.Sprintf("%d scheduled runs have", missed)
	if missed >= cronMaxMissed {
		runs = fmt.Sprintf("%d or more scheduled runs have", cronMaxMissed)
	}
	msg := fmt.Sprintf("%s: %s passed since %s without one succeeding (the first was due %s)", name, runs, since, at(first))
	if missed == 1 {
		msg = fmt.Sprintf("%s: the run due %s has not succeeded (it failed, or never started)", name, at(first))
	}
	if active {
		msg += "; one is running now"
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
