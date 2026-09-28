// Package netcheck is the network half of the check engine: ping and fetching
// a URL, with the judgement about what their outcomes mean.
//
// It is shared by two machines. The Gryphon server runs these checks against a
// host's public address (pkg/checks), and the client agent runs the same ones
// from inside the monitored network, against services the server cannot reach
// (pkg/clientagent). The two used to be one implementation in pkg/checks; it
// lives here so the agent can have it without importing the whole check engine
// and its whois, DNS and database dependencies, and so "what counts as a failed
// ping" has one answer wherever the ping is sent from.
//
// Statuses are pkg/agent's ids, which pkg/checks keeps in step with its own.
package netcheck

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// Outcome is what a network check found.
type Outcome struct {
	// Status is one of the agent.Status* ids.
	Status  int
	Message string
	// RTT is how long the target took to answer. Zero means not measured.
	RTT time.Duration
}

func outcome(status int, msg string, args ...any) Outcome {
	return Outcome{Status: status, Message: fmt.Sprintf(msg, args...)}
}

func healthy(msg string, args ...any) Outcome { return outcome(agent.StatusHealthy, msg, args...) }
func problem(msg string, args ...any) Outcome { return outcome(agent.StatusProblem, msg, args...) }
func unknown(msg string, args ...any) Outcome { return outcome(agent.StatusUnknown, msg, args...) }

// NewHTTPClient returns an HTTP client with a real timeout and a connection
// pool. The old code built a bare &http.Client{} per call, which has no timeout
// at all — a host that accepts a connection and then stalls would park a check
// goroutine forever.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// NormalizeHost strips the parts of a stored domain name that are not part of
// the host: a scheme, a path, and any trailing slash.
func NormalizeHost(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// RoundRTT rounds a response time for a message: to a tenth of a millisecond,
// or to a microsecond below one millisecond.
func RoundRTT(d time.Duration) time.Duration {
	if d >= time.Millisecond {
		return d.Round(100 * time.Microsecond)
	}
	return d.Round(time.Microsecond)
}
