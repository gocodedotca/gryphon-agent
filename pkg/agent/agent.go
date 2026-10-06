// Package agent defines the wire protocol between Gryphon and the client
// agent that runs on monitored hosts. Both sides import these types, so the
// protocol has exactly one definition and cannot drift.
package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Status ids, matching pkg/checks.Status and the services table. Redeclared
// as plain ints so the client binary does not pull in the whole check engine
// (and its ping/whois/TLS dependencies); a test in pkg/checks keeps the two
// sets in step.
const (
	StatusHealthy = 1
	StatusProblem = 2
	StatusPending = 3
	StatusWarning = 4
	// StatusUnknown means the agent could not carry the measurement out.
	// "I could not read the disk" is not the claim "the disk is full"; the
	// server treats unknown as an absence of information, never as an outage.
	StatusUnknown = 5
)

// CheckDeadline is how long an agent gives any one check before it answers
// without a result.
//
// It exists so that "the agent did not answer" means the agent is down, not
// that one check on it is slow. Without a deadline of its own, a check that
// runs on -- a Redis that accepts the connection and never replies to PING, a
// ping whose ICMP, retry and TCP fallback stack up -- outlasts the agent's
// write timeout or the server's, and the server can only report a dropped
// connection: the same message, and the same "not responding" on the overview,
// as an agent that is switched off. Past the deadline the agent answers
// unknown itself, which the server reads as an agent that answered.
//
// Both sides depend on it: the agent's write timeout and the server's check
// timeout must each leave room beyond it, and tests on each side hold them to
// that.
const CheckDeadline = 15 * time.Second

// BearerToken reads "Authorization: Bearer <token>": the agent's token as it
// connects, and a vantage's key. The scheme is matched
// without regard to case, as RFC 9110 says it is. A token longer than any key
// could be is not a token.
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > MaxKeyLength {
		return "", false
	}
	return token, true
}

// KeyMatcher returns a function reporting whether a presented key is want.
//
// Both sides are hashed before they are compared, so the comparison is constant
// time and also constant length: subtle.ConstantTimeCompare returns at once on
// a length mismatch, which would tell a caller how long the key is.
//
// A want that ValidateKey refuses matches nothing, so an empty configured key
// can never match an empty header.
func KeyMatcher(want string) func(presented string) bool {
	usable := ValidateKey(want) == nil
	wantSum := sha256.Sum256([]byte(want))
	return func(presented string) bool {
		got := sha256.Sum256([]byte(presented))
		return usable && subtle.ConstantTimeCompare(got[:], wantSum[:]) == 1
	}
}

// MinKeyLength is the shortest access key either side accepts. A key from
// GenerateKey is 43 characters; `openssl rand -base64 32` is 44. Thirty-two
// leaves room for either and refuses a password somebody made up.
const MinKeyLength = 32

// MaxKeyLength bounds what is stored and hashed. Nothing legitimate is close.
const MaxKeyLength = 256

// ErrNoKey is an empty access key.
var ErrNoKey = errors.New("an access key is required")

// ValidateKey reports what is wrong with an access key, or nil. The agent runs
// it on its own key at startup and the server on a key before saving it, so a
// key Gryphon accepts is one an agent will run with.
func ValidateKey(key string) error {
	switch {
	case key == "":
		return ErrNoKey
	case len(key) < MinKeyLength:
		return fmt.Errorf("access key is %d characters; it must be at least %d", len(key), MinKeyLength)
	case len(key) > MaxKeyLength:
		return fmt.Errorf("access key is %d characters; it must be at most %d", len(key), MaxKeyLength)
	case strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r > '~' }):
		return errors.New("access key must be printable ASCII with no spaces")
	}
	return nil
}

// GenerateKey returns a new random access key: 256 bits, base64url without
// padding, so it can be pasted into a shell, JSON or YAML without quoting.
func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Response is what the agent returns for a check.
type Response struct {
	Action   string    `json:"action"`
	OK       bool      `json:"ok"`
	Status   string    `json:"status"`
	Data     string    `json:"data"`
	DateTime time.Time `json:"date_time"`
	// NewStatusID is the agent's verdict, for the checks that make one: the
	// database checks, which are pass/fail, and any check that could not run at
	// all, which is StatusUnknown.
	//
	// A sensor check makes no verdict and leaves this zero. It has no
	// thresholds to compare against -- those live on the server, per host
	// service -- and an agent that guessed here would be a second place for
	// alerting policy to live.
	NewStatusID int `json:"new_status_id"`

	// Measurement is what a sensor check measured, in the units its threshold
	// is expressed in -- a percentage for disk, memory and CPU; load per core
	// for load. The agent divides by its own CPU count so that a threshold
	// means the same thing on a 4-core and a 64-core node, which is why the
	// value is normalised on the side that knows the core count.
	//
	// Nil from the database checks, which have nothing to measure, and from a
	// sensor check that failed to take a reading -- which the server reports as
	// unknown, because a check that measured nothing has told it nothing.
	//
	// A pointer rather than a plain float for the same reason
	// models.HostService.HasRTT exists: "measured, and it was zero" and "not
	// measured" are different facts, and a zero cannot tell them apart.
	Measurement *float64 `json:"measurement,omitempty"`

	// RTT is how long the target took to answer, for the network checks that
	// time it; nanoseconds on the wire, absent when nothing was timed. It is
	// the agent's round trip to the service, not the server's to the agent.
	RTT time.Duration `json:"rtt_ns,omitempty"`

	// Version is the agent's build, on every answer, so the server can show
	// which agent a host runs and say "this agent is too old for that check"
	// instead of "404". Checks is the check names this agent answers, sent
	// with /test and with a refusal of a check it does not know.
	Version string   `json:"version,omitempty"`
	Checks  []string `json:"checks,omitempty"`
}

// UnknownCheckStatus is the Status an agent answers with, alongside a 404,
// for a check it does not know: an older build asked for a newer check.
const UnknownCheckStatus = "unknown check"

// The network checks' parameters. Each is a URL query string rather than a
// bare value so that a check can grow a setting -- HTTPS's certificate
// verification is the first -- without the agent having to guess which shape
// of string it was handed.
const (
	// ParamURL is the address an http or https check fetches.
	ParamURL = "url"
	// ParamVerify is "false" to accept a certificate that does not verify, for
	// an internal service with a self-signed one. Anything else verifies.
	ParamVerify = "verify"
	// ParamHost is the name or address a ping check pings.
	ParamHost = "host"

	// ParamService is the name of the Swarm service a swarm-service check
	// asks the Docker Engine about.
	ParamService = "service"
	// ParamStack is the name of the Swarm stack a swarm-stack check asks
	// about: every service deployed under that name.
	ParamStack = "stack"
	// ParamContainer is the name (or id) of the container the container,
	// container-memory and container-cpu checks inspect on the agent's node.
	ParamContainer = "container"

	// ParamMethod, ParamStatus and ParamContains are what an http or https
	// check asks of the response: the request method (GET when absent), the
	// status codes that count as up ("200-299" when absent), and text the
	// body must contain (nothing when absent). Absent means what the check
	// did before they existed, so a server only sends the ones it changed.
	ParamMethod   = "method"
	ParamStatus   = "status"
	ParamContains = "contains"

	// The tcp check's settings. ParamHost is the address it dials, as for
	// ping. ParamTLS is netcheck.TLSNone, TLSVerify or TLSNoVerify. ParamSend
	// and ParamExpect are the bytes written after connecting and the bytes
	// the response must contain, both written with the escapes
	// netcheck.DecodeEscapes reads; a check with neither only connects.
	ParamPort   = "port"
	ParamTLS    = "tls"
	ParamSend   = "send"
	ParamExpect = "expect"

	// ParamScript is the file name of the executable a script check runs,
	// from the directory the agent was configured with. Never a path; see
	// ValidScriptName.
	ParamScript = "script"

	// The file-age check's settings. ParamPath is an absolute path inside
	// one of the folders the agent was told it may look in: a file, or a
	// folder whose newest file is judged. ParamPattern narrows a folder to
	// the names matching a glob ("*.sql.gz"). ParamMinSize is a size in
	// bytes, as digits, below which the file is a problem; absent means any
	// size will do.
	ParamPath    = "path"
	ParamPattern = "pattern"
	ParamMinSize = "min_size"

	// The Kubernetes checks' settings. ParamNamespace is the namespace the
	// thing asked about is in, and ParamName its name. ParamKind is the kind
	// of workload a k8s-workload check reads: deployment, statefulset or
	// daemonset. ParamSelector is a label selector in kubectl's syntax
	// (app.kubernetes.io/part-of=shop), which the API server parses; it
	// narrows the app, nodes and pods checks. ParamRestarts is how many
	// restarts of one container make a warning, and ParamWindow, in minutes,
	// how recent the last of them must be to count; both as digits.
	ParamNamespace = "namespace"
	ParamName      = "name"
	ParamKind      = "kind"
	ParamSelector  = "selector"
	ParamRestarts  = "restarts"
	ParamWindow    = "window"
)

// MaxScriptName bounds a script check's name.
const MaxScriptName = 64

// ValidScriptName reports whether name can name a script: letters, digits,
// dots, dashes and underscores, not starting with a dot or a dash. That rules
// out a path, a parent directory and a hidden file by construction, rather
// than by cleaning a path and hoping. The server refuses anything else on
// save and the agent refuses it again before touching the file system.
func ValidScriptName(name string) bool {
	if name == "" || len(name) > MaxScriptName || name[0] == '.' || name[0] == '-' {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ParseSize reads a size as a person writes one -- "500", "10 KB", "1.5MB",
// "2 GiB" -- into bytes. Units are binary, as ls -lh and du report them: a KB
// is 1024 bytes. The server reads the form's value with it before storing the
// check, and sends the agent the bytes, so the two cannot disagree about what
// "1 MB" meant.
func ParseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0, errors.New("no size given")
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	number, unit := s[:i], strings.TrimSuffix(strings.TrimSuffix(s[i:], "IB"), "B")
	if number == "" {
		return 0, fmt.Errorf("%q does not start with a number", s)
	}
	var value float64
	if _, err := fmt.Sscanf(number, "%g", &value); err != nil {
		return 0, fmt.Errorf("%q is not a number", number)
	}
	multiplier := map[string]float64{"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
	m, ok := multiplier[unit]
	if !ok {
		return 0, fmt.Errorf("%q is not a size unit: use B, KB, MB, GB or TB", s[i:])
	}
	bytes := value * m
	if bytes < 0 || bytes > 1<<62 {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return int64(bytes), nil
}

// FormatSize says a size in bytes the way ParseSize reads one.
func FormatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	value := float64(n) / float64(div)
	suffix := []string{"KB", "MB", "GB", "TB"}[exp]
	if value >= 100 || value == float64(int64(value)) {
		return fmt.Sprintf("%.0f %s", value, suffix)
	}
	return fmt.Sprintf("%.1f %s", value, suffix)
}

// HumanDuration says a duration the way a message should: in the largest
// whole unit, and the next one down when that adds something, so a day and a
// half is "1 day 12 hours" and not "36 hours" or "1 day".
func HumanDuration(d time.Duration) string {
	if d < time.Minute {
		return plural(int(d/time.Second), "second")
	}
	units := []struct {
		d    time.Duration
		name string
	}{
		{24 * time.Hour, "day"},
		{time.Hour, "hour"},
		{time.Minute, "minute"},
	}
	for i, u := range units {
		if d < u.d {
			continue
		}
		whole := int(d / u.d)
		out := plural(whole, u.name)
		if i+1 < len(units) {
			next := units[i+1]
			if rest := int((d % u.d) / next.d); rest > 0 {
				out += " " + plural(rest, next.name)
			}
		}
		return out
	}
	return plural(0, "second")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// The connection.
//
// The agent dials Gryphon and keeps one WebSocket open; Gryphon sends checks
// down it and the agent answers on the same connection. Nothing listens on the
// monitored host. Every message is one JSON Frame in a text message.

// DefaultServer is the Gryphon an agent connects to unless told otherwise.
// Compiled into the agent so that a customer only ever supplies a token, and
// read by the server so that the install steps it shows leave the address out
// when it is this one.
const DefaultServer = "https://gryphon.gocode.ca"

// ConnectPath is where the agent connects, under the server's address.
const ConnectPath = "/agent/v1/connect"

// Subprotocol names this version of the protocol in the WebSocket handshake.
// A server that does not offer it refuses the connection, which is how an
// agent too old or too new for the server is told so, before any frame is
// read wrong.
const Subprotocol = "gryphon-agent.v1"

// MaxFrameSize bounds one frame in either direction. It is the bound the
// server used to put on an agent's HTTP answer; nothing legitimate is close.
const MaxFrameSize = 1 << 20

// KeepaliveInterval is how often each side pings the other. It sits under the
// sixty seconds reverse proxies commonly allow an idle connection, so a quiet
// agent is not cut off between checks, and it bounds how long a dead
// connection goes unnoticed.
const KeepaliveInterval = 25 * time.Second

// Close codes the server ends a connection with, from the range RFC 6455
// leaves to applications.
const (
	// CloseRevoked: the token this agent connected with was replaced or its
	// host deleted. Reconnecting with it will be refused, so the agent waits
	// as long as for any refusal before it tries again.
	CloseRevoked = 4001
	// CloseReplaced: another connection presented the same token. Usually
	// this agent restarting before the server noticed its old connection had
	// died, in which case nothing hears this; otherwise the token is
	// installed on two machines, which the server shows on the host.
	CloseReplaced = 4002
)

// Frame types.
const (
	// FrameHello is the agent's first frame on every connection: which build
	// it is and what it runs.
	FrameHello = "hello"
	// FrameRun asks the agent to run Check with Parameters.
	FrameRun = "run"
	// FrameTest asks the agent to say it is there: the round trip behind
	// "Test agent".
	FrameTest = "test"
	// FrameResult answers a run or a test, carrying its ID.
	FrameResult = "result"
)

// Frame is one message on the connection. Type says which fields are set.
type Frame struct {
	Type string `json:"type"`
	// ID pairs a result with the run or test it answers. The server chooses
	// it; the agent only echoes it.
	ID string `json:"id,omitempty"`

	// Check and Parameters, on a run: the check's name (what used to be the
	// path the server posted to, "disk-space") and its settings, decrypted
	// by the server before sending.
	Check      string `json:"check,omitempty"`
	Parameters string `json:"parameters,omitempty"`

	// Code and Response, on a result. Code keeps the meanings the HTTP status
	// had, so the server reads an answer the way it always has: 200 for an
	// answer, 404 for a check this build does not know (Response.Status is
	// then UnknownCheckStatus), 400 for a run it could not read, 500 for a
	// check that panicked.
	Code     int       `json:"code,omitempty"`
	Response *Response `json:"response,omitempty"`

	// Hello, on a hello.
	Hello *Hello `json:"hello,omitempty"`
}

// Hello is what the agent says about itself when it connects.
type Hello struct {
	Version  string   `json:"version"`
	Checks   []string `json:"checks"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Hostname string   `json:"hostname"`
	// Kubernetes is set only by an agent running inside a cluster, which is
	// the one place it can answer the Kubernetes checks.
	Kubernetes *KubernetesInfo `json:"kubernetes,omitempty"`
}

// KubernetesInfo is what an agent inside a cluster says about the cluster.
// Hostname is no use there: it is the pod's name, and changes with every
// restart.
type KubernetesInfo struct {
	// Version is the API server's gitVersion ("v1.31.2"), empty when the
	// agent could not ask.
	Version string `json:"version,omitempty"`
	// Namespace is the one the agent runs in.
	Namespace string `json:"namespace,omitempty"`
	// Node is the node the agent's pod is on, when the manifest passed it
	// (GWC_NODE_NAME from the downward API).
	Node string `json:"node,omitempty"`
}
