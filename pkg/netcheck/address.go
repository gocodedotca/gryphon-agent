package netcheck

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Where a check is allowed to connect.
//
// Two halves of this application ask that question and want opposite answers,
// which is why the rule lives here rather than in either of them.
//
// The Gryphon server, and every regional vantage, dial an address somebody
// typed into a form from a machine that sits inside Gryphon's own network. A
// check pointed at 10.0.0.5:6379 or at 169.254.169.254 would be answered off
// the account holder's own dashboard, and "connection refused" and
// "authentication failed" are different messages -- enough to map an internal
// network one check at a time. So those checks may reach the public internet
// and nothing else.
//
// The client agent is the mirror image. It runs inside the customer's network
// precisely so that it can reach what the server cannot: a service bound to
// loopback, an address on a private network, a name only the internal resolver
// knows. Reaching those is the whole point of it. But the address it dials is
// still one somebody typed into a form on the server, and a TCP send/expect
// check will write a line and report what came back -- so an agent that dials
// anywhere is a scanner, and an open relay into the internet, running from
// inside the network it was installed to protect. It may reach what is inside
// that network and nothing else.
//
// Neither may reach the addresses that are nobody's service: link-local (which
// is where every cloud's metadata endpoint lives), multicast, and the
// unspecified address.

// Scope is where an address lives.
type Scope int

const (
	// ScopePublic is a global unicast address on the public internet.
	ScopePublic Scope = iota
	// ScopePrivate is inside somebody's network: loopback, RFC 1918, IPv6
	// unique local, or RFC 6598 shared address space.
	ScopePrivate
	// ScopeReserved is an address no check may dial from anywhere.
	ScopeReserved
)

// cgnat is RFC 6598 shared address space, which netip does not classify.
// Providers put customer infrastructure behind it, so it is as much "inside"
// as RFC 1918 is.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Classify says which scope addr falls in, and names the kind of address it is
// the way a refusal reads: "10.0.0.5 is " + kind.
func Classify(addr netip.Addr) (Scope, string) {
	// An IPv4 address wearing an IPv6 coat is still that address, and
	// ::ffff:10.0.0.1 must not get past a rule that 10.0.0.1 would fail.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	switch {
	case addr.IsLoopback():
		return ScopePrivate, "a loopback address"
	case addr.IsPrivate():
		return ScopePrivate, "a private address"
	case addr.Is4() && cgnat.Contains(addr):
		return ScopePrivate, "a shared-address-space address"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		// 169.254.169.254, the cloud metadata address, is in here.
		return ScopeReserved, "a link-local address"
	case addr.IsUnspecified():
		return ScopeReserved, "not a routable address"
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return ScopeReserved, "a multicast address"
	case !addr.IsGlobalUnicast():
		return ScopeReserved, "not a global unicast address"
	}
	return ScopePublic, "a public address"
}

// Reach is the set of addresses a policy permits.
type Reach int

const (
	// ReachPublic permits the public internet only. The checks the Gryphon
	// server performs itself, and every check a vantage runs.
	ReachPublic Reach = iota
	// ReachPrivate permits addresses inside the agent's own network only: what
	// the agent exists to reach, and no more.
	ReachPrivate
	// ReachAny permits everything, reserved addresses included. What an
	// operator gets when they say so in as many words.
	ReachAny
)

// BlockedError is an address a Reach refuses.
type BlockedError struct {
	Addr netip.Addr
	// Kind is Classify's name for it, so the sentence reads "10.0.0.5 is a
	// private address".
	Kind string
}

func (e *BlockedError) Error() string { return e.Addr.String() + " is " + e.Kind }

// Permit reports why addr may not be dialled, or nil if it may.
//
// For a check that does not dial through Dialer -- ping sends ICMP to an
// address it resolved itself -- and so has to ask before it sends anything.
func (r Reach) Permit(addr netip.Addr) error {
	if r == ReachAny {
		return nil
	}
	scope, kind := Classify(addr)
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	blocked := &BlockedError{Addr: addr, Kind: kind}

	switch {
	case scope == ScopeReserved:
		return blocked
	case r == ReachPublic && scope == ScopePrivate:
		return blocked
	case r == ReachPrivate && scope == ScopePublic:
		return blocked
	}
	return nil
}

// Dialer returns a dialer that refuses the addresses this reach forbids.
//
// The decision is made in Control, which the runtime calls after the name has
// been resolved and before the socket connects, and which is handed the address
// actually about to be dialled. Checking the hostname instead would decide
// nothing: a name under the account holder's control can resolve to whatever
// they like, and checking a resolved address and then dialling the name again
// leaves a window where the second lookup answers differently. There is no
// window here -- what is inspected is what is connected to.
//
// It matters most for the agent, where an internal name resolving to a private
// address is the ordinary case: the name cannot be judged, only the address it
// arrives at.
func (r Reach) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				// Control is documented as receiving a resolved address, so
				// this should not happen. Refusing an address we cannot parse
				// is the safe direction.
				return fmt.Errorf("cannot parse the address being dialled (%q): %w", address, err)
			}
			return r.Permit(ap.Addr())
		},
	}
}

// HTTPClient is an HTTP client whose every connection -- redirects included --
// is dialled through this reach.
//
// It uses no proxy. The rule judges the address actually dialled, and through
// a proxy that is the proxy's, which would let any target through a permitted
// proxy and refuse every target behind a forbidden one.
// ReachAny is no rule at all, so it keeps the ordinary client, proxy included:
// turning the rule off should not quietly take a proxy away with it.
func (r Reach) HTTPClient(timeout time.Duration) *http.Client {
	client := NewHTTPClient(timeout)
	if r == ReachAny {
		return client
	}
	transport := client.Transport.(*http.Transport)
	transport.Proxy = nil
	transport.DialContext = r.Dialer(timeout).DialContext
	return client
}

// blockedMarkers are the wordings Classify produces. They are the fallback for
// Blocked, because every database driver wraps a dial error differently and
// some flatten it to a string on the way out, losing the error value.
var blockedMarkers = []string{
	"is a loopback address",
	"is a private address",
	"is a shared-address-space address",
	"is a link-local address",
	"is a multicast address",
	"is a public address",
	"is not a routable address",
	"is not a global unicast address",
}

// Blocked reports whether an error came from a Reach refusing an address
// rather than from the target.
//
// It matters which: a refused address is a misconfiguration -- the check is
// pointed somewhere it may not go -- and reporting it as a problem would page
// somebody about a service that is very likely fine. It is unknown, the status
// that means the probe could not be carried out.
func Blocked(err error) bool {
	if err == nil {
		return false
	}
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		return true
	}
	text := err.Error()
	for _, marker := range blockedMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
