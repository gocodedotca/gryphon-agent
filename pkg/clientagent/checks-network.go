package clientagent

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/netcheck"
)

// The network checks: the same HTTP, HTTPS, ping and TCP the Gryphon server runs,
// sent from the monitored host instead. That reaches what the server cannot --
// a service bound to loopback, an address on a private network, a name only the
// internal resolver knows -- and it is judged by the same code, netcheck, so a
// failed ping means the same thing from either side.
//
// What the agent fetches is whatever Gryphon asks for, within the addresses
// reach.go allows it; the access key is what stands between that and anybody
// else.  The answer carries a status line and never a body.

// httpTimeout bounds one fetch. Well inside the server's WriteTimeout, so a
// slow service is reported as slow rather than as an agent that hung up.
const httpTimeout = 10 * time.Second

// netProbe runs the checks that dial an address the server named. Everything
// the reach decides is settled once, here, rather than at each call: the two
// HTTP clients, the pinger and the dialer all carry the same rule, so there is
// no path to a socket that skipped it.
type netProbe struct {
	// client verifies certificates; insecure does not, for a check that has
	// asked not to -- an internal service with a self-signed certificate is
	// the ordinary case for a check run from inside the network.
	client   *http.Client
	insecure *http.Client
	pinger   netcheck.Pinger
	dial     netcheck.DialFunc
	// mysqlNetwork is the name the MySQL driver reaches dial by; see
	// registerMySQLNetwork.
	mysqlNetwork string
}

func newNetProbe(reach netcheck.Reach) *netProbe {
	insecure := reach.HTTPClient(httpTimeout)
	insecure.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // asked for, for self-signed internal services

	dialer := reach.Dialer(dialTimeout)

	n := &netProbe{
		client:   reach.HTTPClient(httpTimeout),
		insecure: insecure,
		// The server's default ping, echo for echo, held to the same rule:
		// Permit judges the resolved address before an echo is sent, and
		// Dialer carries it into the TCP fallback.
		pinger: netcheck.Pinger{
			Count:              4,
			Interval:           200 * time.Millisecond,
			Timeout:            4 * time.Second,
			LossWarning:        0.25,
			TCPFallbackPorts:   []int{443, 80, 22},
			TCPFallbackTimeout: 2 * time.Second,
			Permit:             reach.Permit,
			Dialer:             dialer,
			RefusedMessage:     refusedMessage,
		},
		dial: dialer.DialContext,
	}
	n.mysqlNetwork = n.registerMySQLNetwork()
	return n
}

func fromOutcome(o netcheck.Outcome) result {
	return result{statusID: o.Status, msg: o.Message, rtt: o.RTT}
}

// checkHTTP fetches the URL in params, which must use scheme: the https check
// does not quietly fetch http, and the other way round.
func (n *netProbe) checkHTTP(ctx context.Context, scheme, params string) result {
	values, err := url.ParseQuery(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: "could not read the check's settings: " + err.Error()}
	}
	raw := strings.TrimSpace(values.Get(agent.ParamURL))
	if raw == "" {
		return result{statusID: agent.StatusUnknown, msg: "no URL configured"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return result{statusID: agent.StatusUnknown, msg: raw + " is not a URL the agent can fetch"}
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return result{statusID: agent.StatusUnknown, msg: raw + " is not an " + scheme + ":// URL"}
	}

	spec, err := netcheck.ParseFetchSpec(values.Get)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: "could not read the check's settings: " + err.Error()}
	}
	// A redirect is dialled through the same rule, so a permitted address
	// cannot forward the fetch to a forbidden one.
	spec.Refused = netcheck.Blocked
	spec.RefusedMessage = refusedMessage

	client := n.client
	if scheme == "https" && strings.EqualFold(values.Get(agent.ParamVerify), "false") {
		client = n.insecure
	}
	return fromOutcome(netcheck.FetchWith(ctx, client, u.String(), spec))
}

// checkTCP connects to the address in params and, for a send/expect check,
// has its one exchange.
//
// This is the check with the widest reach of any the agent runs -- any port,
// and text of the caller's choosing written to it -- so it is the one the rule
// in reach.go matters most for.
func (n *netProbe) checkTCP(ctx context.Context, params string) result {
	target, err := netcheck.ParseTCPParameters(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: "could not read the check's settings: " + err.Error()}
	}
	if target.Host == "" {
		return result{statusID: agent.StatusUnknown, msg: "no host configured"}
	}
	rtt, err := netcheck.TCPProbe(ctx, n.dial, target)
	if netcheck.Blocked(err) {
		return refused()
	}
	return fromOutcome(netcheck.TCPOutcome(ctx, target, rtt, err))
}

// checkPing pings the host in params.
func (n *netProbe) checkPing(ctx context.Context, params string) result {
	values, err := url.ParseQuery(params)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: "could not read the check's settings: " + err.Error()}
	}
	host := netcheck.NormalizeHost(values.Get(agent.ParamHost))
	if host == "" {
		return result{statusID: agent.StatusUnknown, msg: "no host configured"}
	}
	return fromOutcome(n.pinger.Ping(ctx, host))
}
