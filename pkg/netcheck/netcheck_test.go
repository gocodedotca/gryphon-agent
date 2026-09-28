package netcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

func testPinger() Pinger {
	return Pinger{
		Count:            2,
		Interval:         50 * time.Millisecond,
		Timeout:          2 * time.Second,
		LossWarning:      0.25,
		TCPFallbackPorts: []int{443, 80, 22},
	}
}

// A refused TCP connection still proves the host is alive: something sent back
// an RST. Only a timeout means we did not find it.
func TestTCPProbeTreatsRefusedAsAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // now nothing is listening, so connecting gets refused

	p := testPinger()
	p.TCPFallbackPorts = []int{port}

	gotPort, alive := p.tcpProbe(context.Background(), "127.0.0.1")
	if !alive {
		t.Errorf("tcpProbe(127.0.0.1:%d) = not alive; a refused connection proves the host is up", port)
	}
	if gotPort != port {
		t.Errorf("port = %d, want %d", gotPort, port)
	}
}

func TestTCPProbeFindsListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	p := testPinger()
	p.TCPFallbackPorts = []int{port}

	gotPort, alive := p.tcpProbe(context.Background(), "127.0.0.1")
	if !alive || gotPort != port {
		t.Errorf("tcpProbe = (%d, %v), want (%d, true)", gotPort, alive, port)
	}
}

// Loopback is always up, so it is never a problem; it is healthy, or unknown
// where neither ICMP nor any fallback port is available to the test.
func TestPingLoopbackIsNeverAProblem(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := testPinger().Ping(ctx, "127.0.0.1")
	if got.Status != agent.StatusHealthy && got.Status != agent.StatusUnknown {
		t.Errorf("status = %d (%q), want healthy or unknown", got.Status, got.Message)
	}
}

// A pinger with a permit rule asks it about the address before sending
// anything, and a refusal is unknown: the check was pointed somewhere this
// installation will not go, which says nothing about the target.
func TestPingAsksPermitBeforeSending(t *testing.T) {
	var asked []netip.Addr
	p := testPinger()
	p.Permit = func(a netip.Addr) error {
		asked = append(asked, a)
		return errors.New("refused")
	}

	start := time.Now()
	got := p.Ping(context.Background(), "127.0.0.1")
	if got.Status != agent.StatusUnknown {
		t.Errorf("status = %d (%q), want unknown", got.Status, got.Message)
	}
	// The IPv4 address, not its 16-byte IPv6 spelling, so a rule written for
	// 127.0.0.0/8 sees what it expects.
	if len(asked) != 1 || asked[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("permit was asked about %v, want [127.0.0.1]", asked)
	}
	if time.Since(start) > time.Second {
		t.Errorf("a refused ping took %s; it should not have sent any echoes", time.Since(start))
	}
}

// The TCP fallback dials through the pinger's own dialer when it has one, so
// the rule a vantage applies to the echo also holds for the fallback.
func TestTCPProbeUsesTheDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	p := testPinger()
	p.TCPFallbackPorts = []int{port}
	p.Dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
		return errors.New("refused by policy")
	}}

	if _, alive := p.tcpProbe(context.Background(), "127.0.0.1"); alive {
		t.Error("tcpProbe found the port alive through a dialer that refuses every address")
	}
}

func TestFetchTimesTheResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
	}))
	defer srv.Close()

	got := Fetch(context.Background(), NewHTTPClient(5*time.Second), srv.URL)
	if got.Status != agent.StatusHealthy {
		t.Fatalf("status = %d (%q), want healthy", got.Status, got.Message)
	}
	if got.RTT < 5*time.Millisecond {
		t.Errorf("RTT = %s, want at least the handler's 5ms", got.RTT)
	}
}
