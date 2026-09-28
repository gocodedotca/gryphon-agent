package netcheck

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A stub Postgres: enough of the wire protocol to answer an SSLRequest and a
// startup message, scripted per test. The handshake is the thing under test,
// so the stub speaks exactly what a real server would at that point and
// nothing more.

// pgReply is what the stub sends back to a startup message.
type pgReply struct {
	// typ is the message type: 'R' for an authentication request, 'E' for an
	// error. Zero closes the connection without answering.
	typ  byte
	code string
	msg  string
}

// startStubPostgres listens on the loopback. It answers SSLRequest with
// sslAnswer ('N' or 'S'; 'S' is not followed by a TLS handshake here, the
// tests for it use a real server) and every startup message with reply.
// stubReplyDelay holds back each stub server's first answer. Go's clock on
// Windows moves in ticks of up to 15.6ms, so a loopback handshake answered at
// once can finish inside one tick and measure a round trip of zero -- which
// the tests below rightly treat as not measured.
const stubReplyDelay = 20 * time.Millisecond

func startStubPostgres(t *testing.T, sslAnswer byte, reply pgReply) string {
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
			go serveStubPostgres(conn, sslAnswer, reply)
		}
	}()
	return l.Addr().String()
}

func serveStubPostgres(conn net.Conn, sslAnswer byte, reply pgReply) {
	defer func() { _ = conn.Close() }()
	time.Sleep(stubReplyDelay)
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, length-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		code := binary.BigEndian.Uint32(body[:4])
		if code == 80877103 {
			if _, err := conn.Write([]byte{sslAnswer}); err != nil {
				return
			}
			continue
		}
		// A startup message.
		switch reply.typ {
		case 'R':
			// AuthenticationCleartextPassword: R, length 8, code 3.
			_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})
		case 'E':
			var b []byte
			b = append(b, 'S')
			b = append(b, "FATAL"...)
			b = append(b, 0, 'C')
			b = append(b, reply.code...)
			b = append(b, 0, 'M')
			b = append(b, reply.msg...)
			b = append(b, 0, 0)
			msg := []byte{'E'}
			msg = binary.BigEndian.AppendUint32(msg, uint32(len(b)+4))
			msg = append(msg, b...)
			_, _ = conn.Write(msg)
		}
		return
	}
}

func handshake(t *testing.T, addr, sslmode string) (time.Duration, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return PostgresHandshake(ctx, nil, PostgresTarget{Host: host, Port: port, SSLMode: sslmode})
}

func TestPostgresHandshakeAcceptsAnAuthenticationRequest(t *testing.T) {
	addr := startStubPostgres(t, 'N', pgReply{typ: 'R'})
	rtt, err := handshake(t, addr, "prefer")
	if err != nil {
		t.Fatalf("a server asking for a password is accepting connections; got %v", err)
	}
	if rtt <= 0 {
		t.Error("the round trip was not measured")
	}
}

func TestPostgresHandshakeAcceptsARefusedRole(t *testing.T) {
	// The server turning away a role it has never heard of is a server that
	// is up, parsing protocol, and consulting its catalogue -- which is what
	// the check exists to confirm. It is also what every real server says to
	// the probe role.
	for _, tc := range []struct{ code, msg string }{
		{"28000", `no pg_hba.conf entry for host "10.0.0.5", user "gryphon_probe", database "gryphon_probe", no encryption`},
		{"28P01", `password authentication failed for user "gryphon_probe"`},
		{"3D000", `database "gryphon_probe" does not exist`},
	} {
		t.Run(tc.code, func(t *testing.T) {
			addr := startStubPostgres(t, 'N', pgReply{typ: 'E', code: tc.code, msg: tc.msg})
			if _, err := handshake(t, addr, "disable"); err != nil {
				t.Errorf("SQLSTATE %s is the server refusing the probe role, not refusing service; got %v", tc.code, err)
			}
		})
	}
}

func TestPostgresHandshakeReportsAServerThatCannotServe(t *testing.T) {
	// The cases the credentialed check cannot tell from a bad password.
	for _, tc := range []struct{ code, msg string }{
		{"57P03", "the database system is starting up"},
		{"57P03", "the database system is in recovery mode"},
		{"57P01", "terminating connection due to administrator command"},
		{"53300", "sorry, too many clients already"},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			addr := startStubPostgres(t, 'N', pgReply{typ: 'E', code: tc.code, msg: tc.msg})
			_, err := handshake(t, addr, "disable")
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("want a *Refusal, got %v", err)
			}
			if refusal.Code != tc.code || refusal.Message != tc.msg {
				t.Errorf("refusal is %+v, want %s %q", refusal, tc.code, tc.msg)
			}
			// The server's own sentence is what the person reads.
			if got := refusal.Error(); got != tc.msg+" ("+tc.code+")" {
				t.Errorf("message is %q", got)
			}
		})
	}
}

func TestPostgresHandshakeRequiresSSLWhenAsked(t *testing.T) {
	addr := startStubPostgres(t, 'N', pgReply{typ: 'R'})
	_, err := handshake(t, addr, "require")
	if err == nil {
		t.Fatal("sslmode=require against a server that declined SSL was reported healthy")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		t.Errorf("a declined SSL request is not the server refusing service: %v", err)
	}
}

func TestPostgresHandshakeSkipsSSLRequestWhenDisabled(t *testing.T) {
	// A stub that would answer SSLRequest with garbage: if the probe sent one
	// with sslmode=disable, it would fail here.
	addr := startStubPostgres(t, 'X', pgReply{typ: 'R'})
	if _, err := handshake(t, addr, "disable"); err != nil {
		t.Errorf("sslmode=disable still sent an SSL request: %v", err)
	}
}

func TestPostgresHandshakeRejectsSomethingElseListening(t *testing.T) {
	// A listener that is not Postgres: it takes the connection and says
	// nothing. This is a web server, an SSH daemon, a load balancer with
	// nothing behind it -- every reason a port can be open without the
	// database being up.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = conn.Close()
		}
	}()

	_, err = handshake(t, l.Addr().String(), "prefer")
	if err == nil {
		t.Fatal("an SSH banner was accepted as a Postgres server")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		t.Errorf("not-Postgres was reported as Postgres refusing service: %v", err)
	}
}

func TestPostgresHandshakeConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	if _, err := handshake(t, addr, "prefer"); err == nil {
		t.Fatal("nothing listening was reported as accepting connections")
	}
}

func TestPostgresHandshakeHonoursTheDeadline(t *testing.T) {
	// Accepts and never answers.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	host, port, _ := net.SplitHostPort(l.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = PostgresHandshake(ctx, nil, PostgresTarget{Host: host, Port: port, SSLMode: "disable"})
	if err == nil {
		t.Fatal("a silent listener was reported as accepting connections")
	}
	if time.Since(started) > 2*time.Second {
		t.Errorf("the handshake outlived its deadline by a wide margin: %s", time.Since(started))
	}
}

// TestPostgresHandshakeAgainstARealServer runs against the docker-compose
// Postgres when it is up, and is skipped when it is not. The stub tests pin the
// protocol as read; this one checks it is the protocol a real server speaks.
func TestPostgresHandshakeAgainstARealServer(t *testing.T) {
	probe, err := net.DialTimeout("tcp", "127.0.0.1:5432", 500*time.Millisecond)
	if err != nil {
		t.Skip("no Postgres on 127.0.0.1:5432")
	}
	_ = probe.Close()

	for _, mode := range []string{"disable", "prefer"} {
		t.Run(mode, func(t *testing.T) {
			rtt, err := handshake(t, "127.0.0.1:5432", mode)
			if err != nil {
				t.Fatalf("a running Postgres was not reported as accepting connections: %v", err)
			}
			if rtt <= 0 {
				t.Error("the round trip was not measured")
			}
		})
	}
}

func TestParsePostgresConnString(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    PostgresTarget
		signsIn bool
	}{
		{
			in:      "host=db.example.com port=5432 user=watch password=s3cret dbname=app sslmode=disable connect_timeout=5",
			want:    PostgresTarget{Host: "db.example.com", Port: "5432", SSLMode: "disable"},
			signsIn: true,
		},
		{
			in:      "host=db.example.com port=5433 sslmode=require connect_timeout=5",
			want:    PostgresTarget{Host: "db.example.com", Port: "5433", SSLMode: "require"},
			signsIn: false,
		},
		{in: "", want: PostgresTarget{}, signsIn: false},
	} {
		got, signsIn := ParsePostgresConnString(tc.in)
		if got != tc.want || signsIn != tc.signsIn {
			t.Errorf("ParsePostgresConnString(%q) = %+v, %v; want %+v, %v", tc.in, got, signsIn, tc.want, tc.signsIn)
		}
	}
}
