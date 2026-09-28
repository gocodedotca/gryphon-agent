package netcheck

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// A stub MySQL: a protocol-10 greeting, then one scripted reply to whatever
// the client answers with. As with the Postgres stub, it speaks exactly what a
// real server does at that point and nothing more; the tests against real
// servers below check that this is what they do speak.

type mysqlStub struct {
	// version is the server_version in the greeting; a MariaDB one carries
	// the "5.5.5-" prefix a real one does.
	version string
	// capabilities are the greeting's; clientSSL among them offers TLS.
	capabilities uint32
	plugin       string
	// greetErr, when set, is sent as an error packet instead of a greeting:
	// "Too many connections" arrives this way.
	greetErr *mysqlStubErr
	// reply is what the handshake response gets: an OK, an error, or a
	// plugin switch (which the stub then answers with reply2).
	reply  byte
	err    *mysqlStubErr
	reply2 byte
}

type mysqlStubErr struct {
	code uint16
	msg  string
}

func (e *mysqlStubErr) packet() []byte {
	p := []byte{mysqlErr}
	p = binary.LittleEndian.AppendUint16(p, e.code)
	p = append(p, "#HY000"...)
	return append(p, e.msg...)
}

func (st mysqlStub) greeting() []byte {
	p := []byte{10}
	p = append(p, st.version...)
	p = append(p, 0)
	p = append(p, 1, 0, 0, 0)    // connection id
	p = append(p, "12345678"...) // auth data part 1
	p = append(p, 0)             // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(st.capabilities))
	p = append(p, 45)                          // utf8mb4
	p = binary.LittleEndian.AppendUint16(p, 2) // status: autocommit
	p = binary.LittleEndian.AppendUint16(p, uint16(st.capabilities>>16))
	p = append(p, 21)                  // auth data length
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, "123456789012"...)   // auth data part 2
	p = append(p, 0)
	p = append(p, st.plugin...)
	return append(p, 0)
}

func startStubMySQL(t *testing.T, st mysqlStub) string {
	t.Helper()
	if st.capabilities == 0 {
		st.capabilities = clientProtocol41 | clientSecureConnection | clientPluginAuth | clientLongPassword
	}
	if st.plugin == "" {
		st.plugin = "mysql_native_password"
	}
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
				time.Sleep(stubReplyDelay)
				if st.greetErr != nil {
					_ = writeMySQLPacket(conn, 0, st.greetErr.packet())
					return
				}
				_ = writeMySQLPacket(conn, 0, st.greeting())
				seq, resp, err := readMySQLPacket(conn)
				if err != nil {
					return
				}
				// The response must name the probe role and an empty
				// password, or the stub refuses to play along.
				if !strings.Contains(string(resp), probeRole+"\x00\x00") {
					_ = writeMySQLPacket(conn, seq+1, (&mysqlStubErr{1043, "Bad handshake"}).packet())
					return
				}
				switch st.reply {
				case mysqlErr:
					_ = writeMySQLPacket(conn, seq+1, st.err.packet())
				case mysqlAuthSwitch:
					_ = writeMySQLPacket(conn, seq+1, append(append([]byte{mysqlAuthSwitch}, "caching_sha2_password\x00"...), "12345678901234567890\x00"...))
					seq2, _, err := readMySQLPacket(conn)
					if err != nil {
						return
					}
					if st.reply2 == mysqlErr {
						_ = writeMySQLPacket(conn, seq2+1, st.err.packet())
					} else {
						_ = writeMySQLPacket(conn, seq2+1, []byte{mysqlOK, 0, 0, 2, 0, 0, 0})
					}
				default:
					_ = writeMySQLPacket(conn, seq+1, []byte{mysqlOK, 0, 0, 2, 0, 0, 0})
				}
			}()
		}
	}()
	return l.Addr().String()
}

func mysqlHandshake(t *testing.T, addr, tlsMode string) (MySQLGreeting, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return MySQLHandshake(ctx, nil, MySQLTarget{Host: host, Port: port, TLS: tlsMode})
}

var accessDenied = &mysqlStubErr{1045, "Access denied for user 'gryphon_probe'@'10.0.0.5' (using password: NO)"}

func TestMySQLHandshakeAccessDeniedIsAServingServer(t *testing.T) {
	// The expected answer from every real server: it looked the probe role
	// up in its grant tables and turned it away.
	addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlErr, err: accessDenied})
	g, err := mysqlHandshake(t, addr, "false")
	if err != nil {
		t.Fatalf("access denied for the probe role is a working server; got %v", err)
	}
	if g.Version != "8.0.36" {
		t.Errorf("version is %q", g.Version)
	}
	if g.RTT <= 0 {
		t.Error("the round trip was not measured")
	}
}

func TestMySQLHandshakeStripsTheMariaDBPrefix(t *testing.T) {
	addr := startStubMySQL(t, mysqlStub{version: "5.5.5-11.4.2-MariaDB-ubu2404", reply: mysqlErr, err: accessDenied})
	g, err := mysqlHandshake(t, addr, "false")
	if err != nil {
		t.Fatal(err)
	}
	if g.Version != "11.4.2-MariaDB-ubu2404" {
		t.Errorf("version is %q; the 5.5.5- compatibility prefix is for old clients, not for people", g.Version)
	}
}

func TestMySQLHandshakeAcceptsAnOK(t *testing.T) {
	// A server with an empty-password account of the probe's name would let
	// it in. Unlikely, and still a server that is up.
	addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlOK})
	if _, err := mysqlHandshake(t, addr, "false"); err != nil {
		t.Errorf("an OK was not healthy: %v", err)
	}
}

func TestMySQLHandshakeFollowsAPluginSwitch(t *testing.T) {
	addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlAuthSwitch, reply2: mysqlErr, err: accessDenied})
	if _, err := mysqlHandshake(t, addr, "false"); err != nil {
		t.Errorf("a plugin switch followed by access denied was not healthy: %v", err)
	}
}

func TestMySQLHandshakeReportsAServerThatCannotServe(t *testing.T) {
	t.Run("too many connections, instead of a greeting", func(t *testing.T) {
		addr := startStubMySQL(t, mysqlStub{greetErr: &mysqlStubErr{1040, "Too many connections"}})
		g, err := mysqlHandshake(t, addr, "false")
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			t.Fatalf("want a *Refusal, got %v", err)
		}
		if refusal.Code != "1040" || refusal.Message != "Too many connections" {
			t.Errorf("refusal is %+v", refusal)
		}
		if g.Version != "" {
			t.Errorf("a version was invented: %q", g.Version)
		}
	})
	t.Run("shutting down, after the greeting", func(t *testing.T) {
		addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlErr, err: &mysqlStubErr{1053, "Server shutdown in progress"}})
		_, err := mysqlHandshake(t, addr, "false")
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			t.Fatalf("want a *Refusal, got %v", err)
		}
		if refusal.Error() != "Server shutdown in progress (1053)" {
			t.Errorf("message is %q", refusal.Error())
		}
	})
}

func TestMySQLHandshakeHostNotAllowedIsAServingServer(t *testing.T) {
	// The server's access rules refusing this address, before or after the
	// greeting, are about us. It is up.
	for name, st := range map[string]mysqlStub{
		"before the greeting": {greetErr: &mysqlStubErr{1130, "Host '10.0.0.5' is not allowed to connect to this MySQL server"}},
		"after the greeting":  {version: "8.0.36", reply: mysqlErr, err: &mysqlStubErr{1130, "Host '10.0.0.5' is not allowed to connect to this MySQL server"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mysqlHandshake(t, startStubMySQL(t, st), "false"); err != nil {
				t.Errorf("host not allowed was reported as the server refusing service: %v", err)
			}
		})
	}
}

func TestMySQLHandshakeTLS(t *testing.T) {
	t.Run("true against a server without TLS is a problem", func(t *testing.T) {
		addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlErr, err: accessDenied})
		_, err := mysqlHandshake(t, addr, "true")
		if err == nil {
			t.Fatal("tls=true was satisfied by a server that does not offer TLS")
		}
		var refusal *Refusal
		if errors.As(err, &refusal) {
			t.Errorf("a missing TLS capability is not the server refusing service: %v", err)
		}
	})
	t.Run("preferred against a server without TLS goes without", func(t *testing.T) {
		addr := startStubMySQL(t, mysqlStub{version: "8.0.36", reply: mysqlErr, err: accessDenied})
		if _, err := mysqlHandshake(t, addr, "preferred"); err != nil {
			t.Errorf("tls=preferred did not fall back to plaintext: %v", err)
		}
	})
}

func TestMySQLHandshakeRejectsSomethingElseListening(t *testing.T) {
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
	_, err = mysqlHandshake(t, l.Addr().String(), "false")
	if err == nil {
		t.Fatal("an SSH banner was accepted as a MySQL server")
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		t.Errorf("not-MySQL was reported as MySQL refusing service: %v", err)
	}
}

func TestMySQLHandshakeConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if _, err := mysqlHandshake(t, addr, "false"); err == nil {
		t.Fatal("nothing listening was reported as accepting connections")
	}
}

// TestMySQLHandshakeAgainstRealServers runs against a MariaDB on 127.0.0.1:3307
// and a MySQL on 127.0.0.1:3308 when they are up, and skips each that is not.
// Nothing in the repository starts them; the stub tests pin the protocol as
// read, and these say whether real servers speak it -- across the plugins
// they default to, which is where the empty-password shortcut has to hold.
func TestMySQLHandshakeAgainstRealServers(t *testing.T) {
	for _, tc := range []struct{ name, addr, wantIn string }{
		{"mariadb", "127.0.0.1:3307", "MariaDB"},
		{"mysql", "127.0.0.1:3308", "8."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := net.DialTimeout("tcp", tc.addr, 500*time.Millisecond)
			if err != nil {
				t.Skipf("no server on %s", tc.addr)
			}
			_ = probe.Close()
			for _, mode := range []string{"false", "preferred"} {
				g, err := mysqlHandshake(t, tc.addr, mode)
				if err != nil {
					t.Fatalf("tls=%s: a running server was not reported as accepting connections: %v", mode, err)
				}
				if !strings.Contains(g.Version, tc.wantIn) {
					t.Errorf("tls=%s: version %q does not look like %s", mode, g.Version, tc.name)
				}
			}
		})
	}
}
