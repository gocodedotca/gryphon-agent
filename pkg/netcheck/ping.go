package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// Pinger reports whether a host answers.
//
// It sends several echoes rather than one and judges the result on packet loss,
// because a single dropped packet on a container overlay network is normal and
// is not evidence that a host is down. It also separates three outcomes the old
// implementation collapsed into two:
//
//   - the host answered            -> healthy (or degraded, on partial loss)
//   - the host did not answer      -> problem, but only after a TCP probe agrees
//   - we could not send the probe  -> unknown, never problem
type Pinger struct {
	Count    int
	Interval time.Duration
	// Timeout caps how long we wait for echo replies, and so how quickly a host
	// that is genuinely down gets reported. It is not the overall check budget.
	Timeout            time.Duration
	LossWarning        float64
	TCPFallbackPorts   []int
	TCPFallbackTimeout time.Duration

	// Permit, when set, is asked about the resolved address before any echo is
	// sent, and a refusal answers unknown. Dialer, when set, dials the TCP
	// fallback, so it can carry the same rule. A regional vantage sets both,
	// because it runs on a cloud server with a metadata address to protect;
	// the server and the agent leave them nil.
	//
	// The address judged is the one pinged: the echoes go to that address, not
	// to the name, so a second lookup cannot answer differently.
	Permit func(netip.Addr) error
	Dialer *net.Dialer
	// RefusedMessage replaces the wording of a refusal by Permit, for the
	// same reason FetchSpec.RefusedMessage does.
	RefusedMessage string
}

// Ping checks host, which may be a name or an address.
func (p Pinger) Ping(ctx context.Context, host string) Outcome {
	addr, res, ok := resolveHost(ctx, host)
	if !ok {
		return res
	}

	if p.Permit != nil {
		ip, parsed := netip.AddrFromSlice(addr)
		if !parsed {
			return unknown("%s - cannot read the resolved address %s", host, addr)
		}
		if err := p.Permit(ip.Unmap()); err != nil {
			if p.RefusedMessage != "" {
				return unknown("%s - %s", host, p.RefusedMessage)
			}
			return unknown("%s - this installation does not allow checks to reach that address", host)
		}
	}

	stats, err := p.icmp(ctx, addr.String())
	if err != nil {
		// We could not open an ICMP socket at all. This is the case inside an
		// unprivileged container, and it says nothing whatsoever about the
		// target — so fall back to TCP rather than reporting a false outage.
		if ctx.Err() != nil {
			return unknown("%s - check cancelled or timed out", host)
		}
		if port, alive := p.tcpProbe(ctx, host); alive {
			return healthy("%s - reachable on tcp/%d (ICMP unavailable to this host: %v)", host, port, err)
		}
		return unknown("%s - cannot send ICMP and no TCP fallback succeeded: %v", host, err)
	}

	loss := stats.PacketLoss / 100

	switch {
	case stats.PacketsRecv == 0:
		// No echo replies. That is often a filtered ICMP rather than a dead
		// host, so ask TCP before calling it an outage.
		if port, alive := p.tcpProbe(ctx, host); alive {
			return healthy("%s - no ICMP reply (filtered), but answering on tcp/%d", host, port)
		}
		return problem("%s - unreachable: %d/%d packets lost, no TCP response",
			host, stats.PacketsSent, stats.PacketsSent)

	case loss > p.LossWarning:
		return Outcome{
			Status: agent.StatusWarning,
			Message: fmt.Sprintf("%s - degraded: %.0f%% packet loss, %s average",
				host, stats.PacketLoss, RoundRTT(stats.AvgRtt)),
			RTT: stats.AvgRtt,
		}

	default:
		return Outcome{
			Status:  agent.StatusHealthy,
			Message: fmt.Sprintf("%s - responded to ping in %s", host, RoundRTT(stats.AvgRtt)),
			RTT:     stats.AvgRtt,
		}
	}
}

// icmp sends the echoes. It tries an unprivileged socket first and falls back to
// a privileged one, since which of the two works depends on the platform and on
// how the process was granted capabilities.
func (p Pinger) icmp(ctx context.Context, addr string) (*probing.Statistics, error) {
	stats, err := p.runPinger(ctx, addr, false)
	if err == nil {
		return stats, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	unprivErr := err

	stats, err = p.runPinger(ctx, addr, true)
	if err == nil {
		return stats, nil
	}
	return nil, fmt.Errorf("unprivileged: %v; privileged: %v", unprivErr, err)
}

func (p Pinger) runPinger(ctx context.Context, addr string, privileged bool) (*probing.Statistics, error) {
	pinger, err := probing.NewPinger(addr)
	if err != nil {
		return nil, err
	}
	pinger.Count = p.Count
	pinger.Interval = p.Interval
	pinger.Timeout = p.Timeout
	pinger.SetPrivileged(privileged)

	if err := pinger.RunWithContext(ctx); err != nil {
		return nil, err
	}

	stats := pinger.Statistics()
	if stats.PacketsSent == 0 {
		return nil, errors.New("no packets were sent")
	}
	return stats, nil
}

// tcpProbe reports whether the host answers at the TCP layer, and on which port.
//
// A refused connection counts as alive: something at that address sent back an
// RST, which is proof the host is up even though the port is closed. Only a
// timeout or an unreachable network means we did not find the host.
func (p Pinger) tcpProbe(ctx context.Context, host string) (int, bool) {
	for _, port := range p.TCPFallbackPorts {
		if ctx.Err() != nil {
			return 0, false
		}

		dialCtx, cancel := context.WithTimeout(ctx, p.tcpTimeout())
		d := p.Dialer
		if d == nil {
			d = &net.Dialer{}
		}
		conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		cancel()

		if err == nil {
			_ = conn.Close()
			return port, true
		}
		if isConnectionRefused(err) {
			return port, true
		}
	}
	return 0, false
}

func (p Pinger) tcpTimeout() time.Duration {
	if p.TCPFallbackTimeout > 0 {
		return p.TCPFallbackTimeout
	}
	return 2 * time.Second
}

func isConnectionRefused(err error) bool {
	var se *net.OpError
	if !errors.As(err, &se) {
		return false
	}
	return strings.Contains(strings.ToLower(se.Err.Error()), "connection refused")
}

// resolveHost turns a name into an address, distinguishing a name that does not
// exist (a real, reportable problem) from a resolver that is not answering right
// now (which tells us nothing about the target).
func resolveHost(ctx context.Context, host string) (net.IP, Outcome, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, Outcome{}, true
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsTemporary || dnsErr.IsTimeout {
				return nil, unknown("%s - name server did not answer: %v", host, err), false
			}
			if dnsErr.IsNotFound {
				return nil, problem("%s - name does not resolve", host), false
			}
		}
		return nil, unknown("%s - could not resolve name: %v", host, err), false
	}
	if len(addrs) == 0 {
		return nil, problem("%s - name resolved to no addresses", host), false
	}

	// Prefer IPv4, but accept IPv6 — the old code asked for "ip4:icmp" and so
	// failed outright on an AAAA-only name.
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, Outcome{}, true
		}
	}
	return addrs[0].IP, Outcome{}, true
}
