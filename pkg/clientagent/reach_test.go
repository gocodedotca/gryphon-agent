package clientagent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/netcheck"
)

// testProbe is an agent with its ordinary reach: its own network and no more.
// The tests that dial 127.0.0.1 are testing what the agent is for.
func testProbe(t *testing.T) *netProbe {
	t.Helper()
	return newNetProbe(netcheck.ReachPrivate)
}

// The agent runs inside somebody's network, so a check pointed at the public
// internet is a scanner and a relay out of that network. It refuses, and the
// refusal is made here rather than on the server because here is the only place
// it holds.
func TestAgentRefusesPublicTargets(t *testing.T) {
	reach := (Config{}).reach()
	if reach != netcheck.ReachPrivate {
		t.Fatalf("the default reach is %v, want private", reach)
	}

	for _, addr := range []string{"8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		if err := reach.Permit(netip.MustParseAddr(addr)); err == nil {
			t.Errorf("%s was allowed; the agent may not reach the public internet", addr)
		}
	}
}

func TestAgentAllowsItsOwnNetwork(t *testing.T) {
	reach := (Config{}).reach()

	for _, addr := range []string{"127.0.0.1", "::1", "10.0.0.5", "192.168.1.10", "172.16.4.4", "100.64.0.1", "fc00::1"} {
		if err := reach.Permit(netip.MustParseAddr(addr)); err != nil {
			t.Errorf("%s was refused: %v; the agent exists to reach these", addr, err)
		}
	}
}

// Link-local is refused from either side: it is where every cloud's metadata
// endpoint lives, and an agent on a cloud VM sits right beside one.
func TestAgentRefusesTheMetadataAddress(t *testing.T) {
	if err := (Config{}).reach().Permit(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("the cloud metadata address was allowed")
	}
}

// The escape hatch, for an operator who wants a check on a public service run
// from this host.
func TestAllowPublicTargetsOpensThePublicInternet(t *testing.T) {
	reach := (Config{AllowPublicTargets: true}).reach()
	for _, addr := range []string{"8.8.8.8", "127.0.0.1", "169.254.169.254"} {
		if err := reach.Permit(netip.MustParseAddr(addr)); err != nil {
			t.Errorf("%s was refused with AllowPublicTargets set: %v", addr, err)
		}
	}
}

// The rule has to bite on a real connection, not only in a unit test of the
// predicate: it is made in the dialer's Control hook, and a hook that is never
// wired up refuses nothing. This is the TCP check, which is the one that can be
// pointed at any port and made to write to it.
func TestTCPCheckRefusesAPublicAddress(t *testing.T) {
	// Refused before a packet is sent, which is why this returns at once
	// rather than waiting out a connection to 8.8.8.8:53.
	res := testProbe(t).checkTCP(context.Background(), tcpParams("8.8.8.8", "53"))
	if res.statusID != agent.StatusUnknown {
		t.Fatalf("status %d (%q), want unknown", res.statusID, res.msg)
	}
	if !strings.Contains(res.msg, "inside its own network") {
		t.Errorf("the message does not explain the refusal: %q", res.msg)
	}
}

// And the same check reaches a private address, so the test above is not
// passing because of something unrelated.
func TestTCPCheckReachesItsOwnNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	res := testProbe(t).checkTCP(context.Background(), tcpParams(host, port))
	if res.statusID != agent.StatusHealthy {
		t.Errorf("status %d (%q), want healthy", res.statusID, res.msg)
	}
}

// A refused HTTP check is unknown too, and says so in the agent's own words
// rather than the server's.
func TestHTTPCheckRefusesAPublicAddress(t *testing.T) {
	res := testProbe(t).checkHTTP(context.Background(), "http", httpParams("http://93.184.216.34/"))
	if res.statusID != agent.StatusUnknown {
		t.Fatalf("status %d (%q), want unknown", res.statusID, res.msg)
	}
	if !strings.Contains(res.msg, "inside its own network") {
		t.Errorf("the message does not explain the refusal: %q", res.msg)
	}
}

// A permitted address must not be able to forward the fetch somewhere it may
// not go: the redirect is dialled through the same rule.
func TestHTTPCheckRefusesARedirectOutOfTheNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://93.184.216.34/", http.StatusFound)
	}))
	defer srv.Close()

	res := testProbe(t).checkHTTP(context.Background(), "http", httpParams(srv.URL))
	if res.statusID != agent.StatusUnknown {
		t.Fatalf("status %d (%q), want unknown", res.statusID, res.msg)
	}
}

// A database check dials an address from the same form field, so it is held to
// the same rule -- and each driver has to be told separately.
func TestDatabaseChecksRefusePublicAddresses(t *testing.T) {
	n := testProbe(t)

	for _, tc := range []struct {
		name string
		run  func() result
	}{
		{"postgres", func() result {
			return n.checkPostgres(context.Background(), "host=8.8.8.8 port=5432 sslmode=disable connect_timeout=5")
		}},
		{"postgres with a user", func() result {
			return n.checkPostgres(context.Background(), "host=8.8.8.8 port=5432 user=watch password=p dbname=app sslmode=disable connect_timeout=5")
		}},
		{"mariadb", func() result {
			return n.checkMariaDB(context.Background(), "tcp(8.8.8.8:3306)/?parseTime=true&tls=false&timeout=5s")
		}},
		{"mariadb with a user", func() result {
			return n.checkMariaDB(context.Background(), "watch:p@tcp(8.8.8.8:3306)/app?parseTime=true&tls=false&timeout=5s")
		}},
		{"redis", func() result { return n.checkRedis(context.Background(), "8.8.8.8:6379") }},
		{"redis url", func() result { return n.checkRedis(context.Background(), "redis://:p@8.8.8.8:6379") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.run()
			if res.statusID != agent.StatusUnknown {
				t.Fatalf("status %d (%q), want unknown", res.statusID, res.msg)
			}
			if !strings.Contains(res.msg, "inside its own network") {
				t.Errorf("the message does not explain the refusal: %q", res.msg)
			}
		})
	}
}

// tcpParams and httpParams build the parameter strings the server sends, so a
// test exercises the same parsing a real check does.
func tcpParams(host, port string) string {
	return url.Values{agent.ParamHost: {host}, agent.ParamPort: {port}}.Encode()
}

func httpParams(target string) string {
	return url.Values{agent.ParamURL: {target}}.Encode()
}
