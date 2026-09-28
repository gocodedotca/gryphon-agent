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

// Realm names the agent in the WWW-Authenticate header of a refusal. Gryphon
// sends the host's access key as "Authorization: Bearer <key>", and an agent
// that does not accept it answers 401 with `Bearer realm="gryphon-agent"`.
// The realm is what tells "a Gryphon agent refused this key" apart from a 401
// that a reverse proxy in front of it sent on its own account.
const Realm = "gryphon-agent"

// RefusedKey reports whether a response with this status and WWW-Authenticate
// header is a Gryphon agent refusing the access key, as opposed to any other
// 401 -- one a reverse proxy in front of the agent sent itself, say, which is a
// different problem with a different fix.
func RefusedKey(status int, wwwAuthenticate string) bool {
	return status == 401 && strings.Contains(wwwAuthenticate, `realm="`+Realm+`"`)
}

// BearerToken reads "Authorization: Bearer <token>". The scheme is matched
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

// Request is the body Gryphon posts to the agent.
type Request struct {
	// Parameters is check-specific: a mount point for disk-space, a DSN for
	// the database checks, a query string for the network and Docker checks
	// (see ParamURL). Decrypted by the server before sending.
	Parameters string `json:"parameters"`
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
