package clientagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// The Docker Engine API, over its Unix socket.
//
// This is a few GETs against a socket on the same machine, so it is plain
// net/http with a dialer that speaks "unix" rather than the Docker client
// module, which would bring most of Moby into a binary whose whole point is to
// be small. The paths are unversioned on purpose: the daemon then serves its
// newest API, and every field read here has been in it since Engine 20.10.
//
// Access to the socket is root-equivalent on the host, which is why the agent
// runs only the fixed questions in checks-docker.go against it and never a path
// or query Gryphon supplies. The one thing a check takes from Gryphon -- a
// container or service name -- is held to Docker's own name grammar before it
// goes anywhere near a URL.

// DefaultDockerSocket, where the Docker Engine listens unless told otherwise,
// is per platform: a Unix socket, or on Windows the Engine's named pipe. See
// docker_local_*.go.

// dockerClient is the agent's connection to the Engine.
type dockerClient struct {
	socket string
	// base is the URL the Engine's paths hang off: a placeholder host for
	// the Unix socket, the real one over TCP.
	base string
	http *http.Client
}

func newDockerClient(socket string) *dockerClient {
	// The Engine is usually a Unix socket. "tcp://host:port" reaches it over
	// the network instead -- which in practice means a socket proxy such as
	// docker-socket-proxy in front of it, allowing the read-only questions
	// this agent asks and refusing everything else. The agent's user then
	// needs no membership of the docker group, which is root-equivalent.
	transport := &http.Transport{
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	base := "http://docker"
	if addr, ok := strings.CutPrefix(socket, "tcp://"); ok {
		base = "http://" + addr
	} else if strings.HasPrefix(socket, "http://") {
		base = strings.TrimSuffix(socket, "/")
	} else {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialLocal(ctx, socket)
		}
	}
	return &dockerClient{
		socket: socket,
		base:   base,
		// The request context carries the check's deadline; a client
		// timeout of its own would only compete with it.
		http: &http.Client{Transport: transport},
	}
}

// dockerError is a non-2xx answer from the Engine, with the message it gave.
type dockerError struct {
	status  int
	message string
}

func (e *dockerError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("Docker answered %d", e.status)
	}
	return e.message
}

// notFound reports whether the Engine said the thing asked about does not
// exist, which for a check is a fact about the host rather than a failure to
// measure.
func (e *dockerError) notFound() bool { return e.status == http.StatusNotFound }

// notManager reports the 503 the Engine sends for a swarm question asked of a
// node that is not a manager, or is not in a swarm at all.
func (e *dockerError) notManager() bool {
	return e.status == http.StatusServiceUnavailable &&
		(strings.Contains(e.message, "swarm manager") || strings.Contains(e.message, "not a swarm"))
}

// get fetches path with query and decodes the JSON answer into out.
func (d *dockerClient) get(ctx context.Context, path string, query url.Values, out any) error {
	u := d.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return d.unreachable(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("reading Docker's answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &msg)
		return &dockerError{status: resp.StatusCode, message: strings.TrimSpace(msg.Message)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("reading Docker's answer: %w", err)
	}
	return nil
}

// unreachable turns a dial failure into the sentence an operator needs: the
// two ordinary causes are that Docker is not on this machine and that the
// agent's user may not open the socket, and they have different fixes.
func (d *dockerClient) unreachable(err error) error {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot open %s: permission denied (%s)", d.socket, dockerPermissionHint)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("cannot open %s: not found (is Docker running on this node?)", d.socket)
	}
	// A dial error wraps the cause in several layers; unwrap to the sentence.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return fmt.Errorf("cannot reach Docker at %s: %v", d.socket, opErr.Err)
	}
	if uerr, ok := err.(*url.Error); ok {
		err = uerr.Err
	}
	return fmt.Errorf("cannot reach Docker at %s: %v", d.socket, err)
}

// pipePath turns Docker's spelling of a named pipe, npipe:////./pipe/name (the
// form DOCKER_HOST takes), into the Windows path \\.\pipe\name. ok is false
// for anything that is not an npipe:// address.
func pipePath(socket string) (path string, ok bool) {
	rest, ok := strings.CutPrefix(socket, "npipe://")
	if !ok {
		return "", false
	}
	return strings.ReplaceAll(rest, "/", `\`), true
}

// dockerName is Docker's grammar for a container or service name. Holding a
// name to it before it is placed in a path is what keeps "../services" from
// being a container name.
var dockerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// nameParam reads the named value from a check's query string and holds it to
// dockerName. The error is the message to answer with.
func nameParam(params, key, what string) (string, error) {
	values, err := url.ParseQuery(params)
	if err != nil {
		return "", errors.New("could not read the check's settings: " + err.Error())
	}
	name := strings.TrimSpace(values.Get(key))
	if name == "" {
		return "", errors.New("no " + what + " configured")
	}
	if !dockerName.MatchString(name) {
		return "", fmt.Errorf("%q is not a %s name Docker would accept", name, what)
	}
	return name, nil
}

// The slices of the Engine's answers the checks read. Everything else in the
// documents is left undecoded.

type containerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status        string `json:"Status"`
			FailingStreak int    `json:"FailingStreak"`
			Log           []struct {
				ExitCode int    `json:"ExitCode"`
				Output   string `json:"Output"`
			} `json:"Log"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	HostConfig   struct {
		Memory    int64 `json:"Memory"`
		NanoCPUs  int64 `json:"NanoCpus"`
		CPUQuota  int64 `json:"CpuQuota"`
		CPUPeriod int64 `json:"CpuPeriod"`
	} `json:"HostConfig"`
}

type containerStats struct {
	Read     string `json:"read"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     uint32 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
		Stats struct {
			// cgroup v2 and v1 spell the page cache differently.
			InactiveFile      uint64 `json:"inactive_file"`
			TotalInactiveFile uint64 `json:"total_inactive_file"`
		} `json:"stats"`
	} `json:"memory_stats"`
}

type swarmService struct {
	ID   string `json:"ID"`
	Spec struct {
		Name string `json:"Name"`
		// Labels carries com.docker.stack.namespace for a service deployed
		// by docker stack deploy, which is how a stack is found.
		Labels map[string]string `json:"Labels"`
		Mode   struct {
			Replicated *struct {
				Replicas uint64 `json:"Replicas"`
			} `json:"Replicated"`
			Global *struct{} `json:"Global"`
		} `json:"Mode"`
	} `json:"Spec"`
	// ServiceStatus is only present when the list was asked for it
	// (status=true, Engine 20.10+); older engines leave it nil and the check
	// counts tasks itself.
	ServiceStatus *struct {
		RunningTasks uint64 `json:"RunningTasks"`
		DesiredTasks uint64 `json:"DesiredTasks"`
	} `json:"ServiceStatus"`
	UpdateStatus *struct {
		State   string `json:"State"`
		Message string `json:"Message"`
	} `json:"UpdateStatus"`
}

type swarmTask struct {
	DesiredState string `json:"DesiredState"`
	Status       struct {
		State string `json:"State"`
	} `json:"Status"`
}

func (d *dockerClient) inspectContainer(ctx context.Context, name string) (containerInspect, error) {
	var c containerInspect
	err := d.get(ctx, "/containers/"+url.PathEscape(name)+"/json", nil, &c)
	return c, err
}

// stats takes one reading. With oneShot the Engine answers from the cgroup at
// once; without it the Engine samples twice a second apart so that
// precpu_stats is filled in, which is what a CPU percentage needs.
func (d *dockerClient) stats(ctx context.Context, name string, oneShot bool) (containerStats, error) {
	q := url.Values{"stream": {"false"}}
	if oneShot {
		q.Set("one-shot", "true")
	}
	var s containerStats
	err := d.get(ctx, "/containers/"+url.PathEscape(name)+"/stats", q, &s)
	return s, err
}

// stackLabel is the label docker stack deploy puts on every service it
// creates, naming the stack.
const stackLabel = "com.docker.stack.namespace"

// services lists swarm services matching filters, with their status.
func (d *dockerClient) services(ctx context.Context, filters map[string][]string) ([]swarmService, error) {
	encoded, _ := json.Marshal(filters)
	q := url.Values{"status": {"true"}, "filters": {string(encoded)}}
	var all []swarmService
	if err := d.get(ctx, "/services", q, &all); err != nil {
		return nil, err
	}
	return all, nil
}

// service finds the swarm service called name. The Engine's name filter is a
// prefix match, so the answer is searched for the exact name; ok is false when
// no service has it.
func (d *dockerClient) service(ctx context.Context, name string) (svc swarmService, ok bool, err error) {
	all, err := d.services(ctx, map[string][]string{"name": {name}})
	if err != nil {
		return swarmService{}, false, err
	}
	for _, s := range all {
		if s.Spec.Name == name {
			return s, true, nil
		}
	}
	return swarmService{}, false, nil
}

// stack lists the services deployed under a stack name. The label filter is
// an exact match, so nothing more is checked; an empty answer means no such
// stack.
func (d *dockerClient) stack(ctx context.Context, name string) ([]swarmService, error) {
	return d.services(ctx, map[string][]string{"label": {stackLabel + "=" + name}})
}

// taskCounts is how many of a service's tasks are running against how many
// should be, from ServiceStatus where the Engine reports it and from the
// task list where it does not.
func (d *dockerClient) taskCounts(ctx context.Context, svc swarmService) (running, desired uint64, err error) {
	if svc.ServiceStatus != nil {
		return svc.ServiceStatus.RunningTasks, svc.ServiceStatus.DesiredTasks, nil
	}
	return d.tasks(ctx, svc.ID)
}

// tasks counts a service's tasks the way ServiceStatus would, for an Engine
// too old to report it.
func (d *dockerClient) tasks(ctx context.Context, service string) (running, desired uint64, err error) {
	filters, _ := json.Marshal(map[string][]string{"service": {service}})
	var all []swarmTask
	if err := d.get(ctx, "/tasks", url.Values{"filters": {string(filters)}}, &all); err != nil {
		return 0, 0, err
	}
	for _, t := range all {
		if t.DesiredState != "running" {
			continue
		}
		desired++
		if t.Status.State == "running" {
			running++
		}
	}
	return running, desired, nil
}
