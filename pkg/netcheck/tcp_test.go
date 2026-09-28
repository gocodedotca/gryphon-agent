package netcheck

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// startStubTCP listens on the loopback and hands every connection to serve.
func startStubTCP(t *testing.T, serve func(net.Conn)) TCPTarget {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				serve(conn)
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	return TCPTarget{Host: host, Port: port, TLS: TLSNone}
}

func probe(t *testing.T, target TCPTarget) Outcome {
	t.Helper()
	ctx := context.Background()
	rtt, err := TCPProbe(ctx, nil, target)
	return TCPOutcome(ctx, target, rtt, err)
}

func TestTCPProbe(t *testing.T) {
	smtp := func(conn net.Conn) {
		_, _ = conn.Write([]byte("220 mail.example.com ESMTP\r\n"))
		time.Sleep(time.Second)
	}

	t.Run("an open port is healthy and timed", func(t *testing.T) {
		got := probe(t, startStubTCP(t, func(net.Conn) {}))
		if got.Status != agent.StatusHealthy || got.RTT <= 0 {
			t.Errorf("got %d %q, rtt %s; want healthy and timed", got.Status, got.Message, got.RTT)
		}
	})

	t.Run("a closed port is a problem", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		host, port, _ := net.SplitHostPort(l.Addr().String())
		_ = l.Close()
		got := probe(t, TCPTarget{Host: host, Port: port})
		if got.Status != agent.StatusProblem || !strings.Contains(got.Message, "connection refused") {
			t.Errorf("got %d %q; want a refused problem", got.Status, got.Message)
		}
	})

	t.Run("a greeting that contains the text is healthy", func(t *testing.T) {
		target := startStubTCP(t, smtp)
		target.Expect = []byte("220 ")
		if got := probe(t, target); got.Status != agent.StatusHealthy {
			t.Errorf("got %d %q; want healthy", got.Status, got.Message)
		}
	})

	t.Run("a greeting without the text is a problem that quotes it", func(t *testing.T) {
		target := startStubTCP(t, func(conn net.Conn) { _, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")) })
		target.Expect = []byte("220 ")
		got := probe(t, target)
		if got.Status != agent.StatusProblem {
			t.Fatalf("got %d %q; want problem", got.Status, got.Message)
		}
		if !strings.Contains(got.Message, `"SSH-2.0-OpenSSH_9.6\r\n"`) {
			t.Errorf("message %q does not quote what answered", got.Message)
		}
	})

	t.Run("what is sent is answered", func(t *testing.T) {
		target := startStubTCP(t, func(conn net.Conn) {
			line, _ := bufio.NewReader(conn).ReadString('\n')
			if line == "version\r\n" {
				_, _ = conn.Write([]byte("VERSION 1.6.21\r\n"))
			}
		})
		target.Send = []byte("version\r\n")
		target.Expect = []byte("VERSION")
		if got := probe(t, target); got.Status != agent.StatusHealthy {
			t.Errorf("got %d %q; want healthy", got.Status, got.Message)
		}
	})

	t.Run("silence past the timeout is a problem", func(t *testing.T) {
		defer func(d time.Duration) { tcpTimeout = d }(tcpTimeout)
		tcpTimeout = 200 * time.Millisecond

		target := startStubTCP(t, func(net.Conn) { time.Sleep(time.Second) })
		target.Expect = []byte("220")
		got := probe(t, target)
		if got.Status != agent.StatusProblem || !strings.Contains(got.Message, "got nothing") {
			t.Errorf("got %d %q; want a problem saying nothing arrived", got.Status, got.Message)
		}
	})

	t.Run("a check cancelled from outside is unknown", func(t *testing.T) {
		target := startStubTCP(t, func(net.Conn) { time.Sleep(time.Second) })
		target.Expect = []byte("220")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		rtt, err := TCPProbe(ctx, nil, target)
		if got := TCPOutcome(ctx, target, rtt, err); got.Status != agent.StatusUnknown {
			t.Errorf("got %d %q; want unknown", got.Status, got.Message)
		}
	})

	t.Run("a response past the read limit stops the search", func(t *testing.T) {
		target := startStubTCP(t, func(conn net.Conn) {
			_, _ = conn.Write([]byte(strings.Repeat("x", MaxTCPRead+10)))
			time.Sleep(time.Second)
		})
		target.Expect = []byte("never")
		got := probe(t, target)
		if got.Status != agent.StatusProblem || !strings.Contains(got.Message, "first 4 KB") {
			t.Errorf("got %d %q; want a read-limit problem", got.Status, got.Message)
		}
	})

	t.Run("a name that does not resolve is a problem", func(t *testing.T) {
		got := probe(t, TCPTarget{Host: "no-such-host.invalid", Port: "25"})
		if got.Status != agent.StatusProblem && got.Status != agent.StatusUnknown {
			t.Errorf("got %d %q", got.Status, got.Message)
		}
	})
}

func TestTCPProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	target := TCPTarget{Host: host, Port: port, Send: []byte("GET / HTTP/1.0\r\n\r\n"), Expect: []byte("HTTP/1.0 200")}

	target.TLS = TLSVerify
	if got := probe(t, target); got.Status != agent.StatusProblem || !strings.Contains(got.Message, TLSNoVerify) {
		t.Errorf("verified self-signed: got %d %q; want a problem that suggests %s", got.Status, got.Message, TLSNoVerify)
	}

	target.TLS = TLSNoVerify
	if got := probe(t, target); got.Status != agent.StatusHealthy {
		t.Errorf("unverified: got %d %q; want healthy", got.Status, got.Message)
	}

	target.TLS = TLSNone
	if got := probe(t, target); got.Status != agent.StatusProblem {
		t.Errorf("plain text to a TLS port: got %d %q; want problem", got.Status, got.Message)
	}
}

func TestDecodeEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`QUIT\r\n`:   "QUIT\r\n",
		`a\tb\\c`:    "a\tb\\c",
		`\x1b[0m\0`:  "\x1b[0m\x00",
		`plain text`: "plain text",
	} {
		got, err := DecodeEscapes(in)
		if err != nil || string(got) != want {
			t.Errorf("DecodeEscapes(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{`trailing\`, `\q`, `\x1`, `\xzz`} {
		if _, err := DecodeEscapes(in); err == nil {
			t.Errorf("DecodeEscapes(%q) accepted a broken escape", in)
		}
	}
}

func TestParseTCPParameters(t *testing.T) {
	got, err := ParseTCPParameters("host=db.internal&port=5672&tls=tls&send=PING%5Cr%5Cn&expect=PONG")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "db.internal" || got.Port != "5672" || got.TLS != TLSVerify ||
		string(got.Send) != "PING\r\n" || string(got.Expect) != "PONG" {
		t.Errorf("got %+v", got)
	}

	for _, bad := range []string{"host=h&port=0", "host=h&port=x", "host=h&port=1&tls=sometimes", "host=h&port=1&send=%5Cq"} {
		if _, err := ParseTCPParameters(bad); err == nil {
			t.Errorf("ParseTCPParameters(%q) accepted it", bad)
		}
	}
}

func TestExcerptIsBounded(t *testing.T) {
	got := Excerpt([]byte(strings.Repeat("a", 500)))
	if len(got) > excerptLength+10 || !strings.HasSuffix(got, "…") {
		t.Errorf("Excerpt of 500 bytes = %q; want it cut and marked", got)
	}
	if got := Excerpt([]byte("\x00\"ok\"")); got != `"\x00\"ok\""` {
		t.Errorf("Excerpt = %s", got)
	}
}
