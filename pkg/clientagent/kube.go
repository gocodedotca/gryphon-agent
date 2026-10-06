package clientagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// The Kubernetes API, from inside the cluster.
//
// As with the Docker Engine, this is plain net/http rather than client-go,
// which would bring in dozens of modules and an informer cache to answer a
// question asked every few minutes. The agent only ever reads: every request
// below is a GET built from fixed paths, with the names Gryphon sends held to
// Kubernetes' own grammar first. What it may read is decided by the RBAC the
// cluster's administrator applied, never by anything Gryphon sends.
//
// Only in-cluster: the address comes from the environment the kubelet gives
// every pod, and the credentials from the ServiceAccount files it mounts.
// There is no kubeconfig; see docs/PLAN-kubernetes.md for why.

// serviceAccountDir is where the kubelet mounts a pod's ServiceAccount token,
// CA and namespace.
const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubePageSize is how many objects one list call asks for. The answer is
// decoded into the few fields the checks read, so this bounds a single
// response's size rather than the agent's memory.
var kubePageSize = 250

// kubeMaxPages bounds a list across pages: 40 pages of 250 is ten thousand
// pods, past which a check is asking a question too broad to be one check.
const kubeMaxPages = 40

// kubeClient is the agent's connection to the API server.
type kubeClient struct {
	base string
	// tokenPath is re-read on every request: projected tokens are rotated
	// by the kubelet, about once an hour, by rewriting the file.
	tokenPath string
	namespace string
	node      string
	http      *http.Client
}

// newKubeClient returns the client for the cluster this agent is running in,
// or nil when it is not in one: no KUBERNETES_SERVICE_HOST, or no
// ServiceAccount mounted. nil is the ordinary answer on every machine that is
// not a pod, and the Kubernetes checks are then not offered at all.
//
// dir is where the ServiceAccount files are, serviceAccountDir when empty.
func newKubeClient(getenv func(string) string, node, dir string) *kubeClient {
	if dir == "" {
		dir = serviceAccountDir
	}
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil
	}
	if port == "" {
		port = "443"
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil
	}
	tokenPath := filepath.Join(dir, "token")
	if _, err := os.Stat(tokenPath); err != nil {
		return nil
	}
	ns, _ := os.ReadFile(filepath.Join(dir, "namespace"))

	transport := &http.Transport{
		// The API server is reached directly, by its in-cluster address; an
		// HTTPS_PROXY meant for the way out to Gryphon must not catch it.
		Proxy:           nil,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	return &kubeClient{
		base:      "https://" + net.JoinHostPort(host, port),
		tokenPath: tokenPath,
		namespace: strings.TrimSpace(string(ns)),
		node:      strings.TrimSpace(node),
		// The request context carries the check's deadline, as for Docker.
		http: &http.Client{Transport: transport},
	}
}

// info is what the agent says about its cluster in its hello. The version
// needs a request, which is given a few seconds and otherwise left out: a
// hello must not wait on an API server that is struggling.
func (k *kubeClient) info(ctx context.Context) *agent.KubernetesInfo {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	in := &agent.KubernetesInfo{Namespace: k.namespace, Node: k.node}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := k.get(ctx, "/version", nil, &v); err == nil {
		in.Version = v.GitVersion
	}
	return in
}

// kubeError is a non-2xx answer from the API server: the Status object it
// sends, and what was being asked, so the message can say what to fix.
type kubeError struct {
	status  int
	reason  string
	message string
	// verb, resource and namespace are the request, for a 403's message.
	verb, resource, namespace string
}

func (e *kubeError) Error() string {
	switch e.status {
	case http.StatusUnauthorized:
		return "the Kubernetes API refused the agent's ServiceAccount token"
	case http.StatusForbidden:
		where := "across the cluster"
		fix := "apply gryphon-agent.yaml, the cluster-wide manifest"
		if e.namespace != "" {
			where = "in namespace " + e.namespace
			fix = "apply gryphon-agent-role.yaml in " + e.namespace + ", or the cluster-wide gryphon-agent.yaml"
		}
		return fmt.Sprintf("the agent's ServiceAccount may not %s %s %s (%s)", e.verb, e.resource, where, fix)
	}
	if e.message == "" {
		return fmt.Sprintf("the Kubernetes API answered %d", e.status)
	}
	return "Kubernetes: " + e.message
}

func (e *kubeError) notFound() bool { return e.status == http.StatusNotFound }

func asKubeError(err error, target **kubeError) bool { return errors.As(err, target) }

// token reads the ServiceAccount token as it is now.
func (k *kubeClient) token() (string, error) {
	b, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading the ServiceAccount token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// get fetches path with query and decodes the JSON answer into out.
func (k *kubeClient) get(ctx context.Context, path string, query url.Values, out any) error {
	return k.request(ctx, "get", "", "", path, query, out)
}

// request is get with what is being asked spelt out, for the message a
// refusal gets.
func (k *kubeClient) request(ctx context.Context, verb, resource, namespace, path string, query url.Values, out any) error {
	u := k.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	tok, err := k.token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		if uerr, ok := err.(*url.Error); ok {
			err = uerr.Err
		}
		return fmt.Errorf("cannot reach the Kubernetes API at %s: %v", k.base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &st)
		return &kubeError{status: resp.StatusCode, reason: st.Reason, message: strings.TrimSpace(st.Message),
			verb: verb, resource: resource, namespace: namespace}
	}
	// Decoded as it streams, into only the fields out names: a page of
	// pods is mostly spec nobody here reads.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil {
		return fmt.Errorf("reading the Kubernetes API's answer: %w", err)
	}
	return nil
}

// kubeList is the envelope every list answer comes in.
type kubeList[T any] struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []T `json:"items"`
}

// list fetches every object at path matching selector, across pages.
// resource and namespace name the request for a refusal's message.
func list[T any](ctx context.Context, k *kubeClient, resource, namespace, path, selector string) ([]T, error) {
	var all []T
	q := url.Values{"limit": {fmt.Sprint(kubePageSize)}}
	if selector != "" {
		q.Set("labelSelector", selector)
	}
	for page := 0; ; page++ {
		if page == kubeMaxPages {
			return nil, fmt.Errorf("more than %d %s match; narrow the check with a selector", kubeMaxPages*kubePageSize, resource)
		}
		var l kubeList[T]
		if err := k.request(ctx, "list", resource, namespace, path, q, &l); err != nil {
			return nil, err
		}
		all = append(all, l.Items...)
		if l.Metadata.Continue == "" {
			return all, nil
		}
		q.Set("continue", l.Metadata.Continue)
	}
}

// kubeParams is a Kubernetes check's settings, read and held to grammar.
type kubeParams struct {
	values url.Values
}

func readKubeParams(params string) (kubeParams, error) {
	v, err := url.ParseQuery(params)
	if err != nil {
		return kubeParams{}, errors.New("could not read the check's settings: " + err.Error())
	}
	return kubeParams{values: v}, nil
}

// namespace is the required namespace.
func (p kubeParams) namespace() (string, error) {
	ns := strings.TrimSpace(p.values.Get(agent.ParamNamespace))
	if ns == "" {
		return "", errors.New("no namespace configured")
	}
	// Held to Kubernetes' grammar so that nothing Gryphon sends can be more
	// than a name by the time it is in a path.
	if !agent.ValidKubeNamespace(ns) {
		return "", fmt.Errorf("%q is not a namespace name Kubernetes would accept", ns)
	}
	return ns, nil
}

// name is the required name of the object, as what (a CronJob, a deployment).
func (p kubeParams) name(what string) (string, error) {
	name := strings.TrimSpace(p.values.Get(agent.ParamName))
	if name == "" {
		return "", errors.New("no " + what + " name configured")
	}
	if !agent.ValidKubeName(name) {
		return "", fmt.Errorf("%q is not a %s name Kubernetes would accept", name, what)
	}
	return name, nil
}

// selector is the optional label selector. It goes in a query string, where
// it cannot become a path, and the API server parses it and says what is
// wrong with it; here it is only bounded.
func (p kubeParams) selector() (string, error) {
	sel := strings.TrimSpace(p.values.Get(agent.ParamSelector))
	if problem := agent.KubeSelectorProblem(sel); problem != "" {
		return "", errors.New("the label selector " + problem)
	}
	return sel, nil
}

// count is an optional non-negative whole number, def when absent.
func (p kubeParams) count(key, what string, def int) (int, error) {
	s := strings.TrimSpace(p.values.Get(key))
	if s == "" {
		return def, nil
	}
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil || n < 0 || fmt.Sprint(n) != s {
		return 0, fmt.Errorf("%q is not a whole number of %s", s, what)
	}
	return n, nil
}

// The slices of the API's objects the checks read. Everything else in the
// documents is left undecoded.

type kubeMeta struct {
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	Generation        int64     `json:"generation"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
}

type kubeCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type kubeDeployment struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		// Replicas is a pointer because absent means 1, not 0.
		Replicas *int32 `json:"replicas"`
		Paused   bool   `json:"paused"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64           `json:"observedGeneration"`
		ReadyReplicas      int32           `json:"readyReplicas"`
		UpdatedReplicas    int32           `json:"updatedReplicas"`
		Conditions         []kubeCondition `json:"conditions"`
	} `json:"status"`
}

type kubeStatefulSet struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas int32 `json:"readyReplicas"`
	} `json:"status"`
}

type kubeDaemonSet struct {
	Metadata kubeMeta `json:"metadata"`
	Status   struct {
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
	} `json:"status"`
}

type kubeNode struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		Conditions []kubeCondition `json:"conditions"`
	} `json:"status"`
}

type kubeContainerState struct {
	Waiting *struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"waiting"`
	Terminated *struct {
		Reason     string    `json:"reason"`
		ExitCode   int       `json:"exitCode"`
		FinishedAt time.Time `json:"finishedAt"`
	} `json:"terminated"`
}

type kubeContainerStatus struct {
	Name         string             `json:"name"`
	RestartCount int                `json:"restartCount"`
	State        kubeContainerState `json:"state"`
	LastState    kubeContainerState `json:"lastState"`
}

type kubePod struct {
	Metadata kubeMeta `json:"metadata"`
	Status   struct {
		Phase                 string                `json:"phase"`
		ContainerStatuses     []kubeContainerStatus `json:"containerStatuses"`
		InitContainerStatuses []kubeContainerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type kubeCronJob struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Schedule string  `json:"schedule"`
		TimeZone *string `json:"timeZone"`
		Suspend  *bool   `json:"suspend"`
	} `json:"spec"`
	Status struct {
		Active             []struct{} `json:"active"`
		LastScheduleTime   *time.Time `json:"lastScheduleTime"`
		LastSuccessfulTime *time.Time `json:"lastSuccessfulTime"`
	} `json:"status"`
}
