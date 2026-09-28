package netcheck

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// The Postgres check that does not sign in.
//
// Postgres has no PING. What it has is a startup handshake that says a great
// deal before anybody is authenticated: a server asked to open a session
// answers either by asking for credentials or by saying why it will not, and
// both are the server speaking its own protocol. So this asks for a session as
// a role that does not exist and reads the first reply. It is what pg_isready
// does, and it needs no role, no password and no database on the server.
//
// Which replies count as "up" is the judgement here, and it is a little finer
// than pg_isready's. An authentication request means the server would take a
// session. A FATAL means the server is up and parsing protocol, and most of
// them -- role does not exist, no pg_hba.conf entry, password authentication
// failed -- are the server refusing *this role*, which says nothing about the
// database. The ones that are about the database are class 57, operator
// intervention ("the database system is starting up", "is shutting down", "is
// in recovery mode") and class 53, insufficient resources ("too many
// connections", "out of memory"): a server that would refuse the application
// too. Those are reported as the problem they are, with the server's own
// sentence in the message. That is something the signed-in check cannot do:
// from inside a failed connect, a recovering server and a wrong password look
// alike.
//
// Nothing is logged on the server unless log_connections is on. For password
// authentication the server asks before it checks, and this hangs up when
// asked.

// PostgresTarget is what the handshake needs to know: where, and whether to
// speak TLS.
type PostgresTarget struct {
	Host string
	// Port defaults to 5432.
	Port string
	// SSLMode is the connection string's sslmode, in the driver's vocabulary:
	// disable, prefer or require. Anything else is read as prefer.
	SSLMode string
}

// Refusal is a Postgres server's own answer that it cannot take a
// session right now: up, speaking its protocol, and not serving.
type Refusal struct {
	// Code is the SQLSTATE, such as 57P03.
	Code string
	// Message is the server's sentence, such as "the database system is
	// starting up".
	Message string
}

func (e *Refusal) Error() string {
	if e.Message == "" {
		return "SQLSTATE " + e.Code
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// DialFunc opens a connection, the way net.Dialer.DialContext does.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// probeRole is the role the handshake asks to sign in as. It is not expected to
// exist; the point is that the server answers.
const probeRole = "gryphon_probe"

// PostgresHandshake asks a Postgres server whether it would accept a session,
// without signing in, and reports how long it took to answer.
//
// A nil error means the server is accepting connections. A *Refusal
// means the server answered that it is not. Any other error means the target
// could not be reached, hung up, or did not speak Postgres. dial may be nil for
// a plain net.Dialer; the server passes its outbound policy's.
func PostgresHandshake(ctx context.Context, dial DialFunc, t PostgresTarget) (time.Duration, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	port := strings.TrimSpace(t.Port)
	if port == "" {
		port = "5432"
	}
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return 0, errors.New("no address to connect to")
	}

	started := time.Now()
	raw, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0, err
	}
	defer func() { _ = raw.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}

	conn := raw
	sslmode := strings.ToLower(strings.TrimSpace(t.SSLMode))
	if sslmode != "disable" {
		secured, reply, err := negotiateTLS(ctx, raw, host, sslmode == "require")
		if err != nil {
			return 0, err
		}
		if reply != nil {
			// A server old enough to answer SSLRequest with an error message
			// has still answered as Postgres; judge the message and stop
			// there, as libpq would have to reconnect to go further.
			return time.Since(started), judgeError(reply)
		}
		conn = secured
	}

	if err := writeStartup(conn); err != nil {
		return 0, fmt.Errorf("cannot send a startup message: %w", err)
	}
	typ, body, err := readMessage(conn)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(started)

	switch typ {
	case 'R':
		// AuthenticationOk, or a request for credentials of some kind. Either
		// way the server would open a session.
		return rtt, nil
	case 'E':
		return rtt, judgeError(body)
	default:
		return 0, fmt.Errorf("unexpected reply %q to a startup message; is this Postgres?", typ)
	}
}

// negotiateTLS sends SSLRequest and acts on the one-byte answer.
//
// It returns the connection to continue on -- the TLS session, or the plain
// connection when the server declined and the mode allows it. An old server
// that answers with an ErrorResponse instead is returned as reply, for the
// caller to judge.
func negotiateTLS(ctx context.Context, raw net.Conn, host string, required bool) (conn net.Conn, reply []byte, err error) {
	var msg [8]byte
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], 80877103) // SSLRequest code
	if _, err := raw.Write(msg[:]); err != nil {
		return nil, nil, fmt.Errorf("cannot send an SSL request: %w", err)
	}

	var answer [1]byte
	if _, err := io.ReadFull(raw, answer[:]); err != nil {
		return nil, nil, fmt.Errorf("no answer to an SSL request: %w", err)
	}

	switch answer[0] {
	case 'S':
		// require does not verify the certificate, because libpq's does not
		// and neither does the signed-in check through pgx: a database on a
		// private address almost never has a certificate for its name, and
		// the mode's promise is encryption, not identity.
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:         serverName(host),
			InsecureSkipVerify: true, //nolint:gosec // see above
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil, nil
	case 'N':
		if required {
			return nil, nil, errors.New("the server does not support SSL, and the check requires it")
		}
		return raw, nil, nil
	case 'E':
		body, err := readBody(raw)
		if err != nil {
			return nil, nil, err
		}
		if required {
			return nil, nil, fmt.Errorf("the server refused the SSL request: %s", errorMessage(body))
		}
		return nil, body, nil
	default:
		return nil, nil, fmt.Errorf("unexpected reply %q to an SSL request; is this Postgres?", answer[0])
	}
}

// serverName is the name to send in the TLS handshake: the host, unless it is
// an address, which has no place in SNI.
func serverName(host string) string {
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return ""
	}
	return host
}

// writeStartup sends a StartupMessage for probeRole, with an application name
// so that a server logging connections says who asked.
func writeStartup(conn net.Conn) error {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 196608) // protocol 3.0
	for _, kv := range [][2]string{
		{"user", probeRole},
		{"application_name", "gryphon"},
	} {
		body = append(body, kv[0]...)
		body = append(body, 0)
		body = append(body, kv[1]...)
		body = append(body, 0)
	}
	body = append(body, 0)

	msg := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))
	msg = append(msg, body...)
	_, err := conn.Write(msg)
	return err
}

// maxMessage bounds what the probe will read from a server. A real reply to a
// startup message is a few dozen bytes; a length far beyond that is a server
// that is not Postgres, or one that is, and hostile.
const maxMessage = 64 << 10

// readMessage reads one backend message: its type byte and its body.
func readMessage(conn net.Conn) (byte, []byte, error) {
	var typ [1]byte
	if _, err := io.ReadFull(conn, typ[:]); err != nil {
		return 0, nil, fmt.Errorf("no answer to a startup message: %w", err)
	}
	body, err := readBody(conn)
	if err != nil {
		return 0, nil, err
	}
	return typ[0], body, nil
}

// readBody reads a message's length and then that many bytes, the type byte
// having already been consumed.
func readBody(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("truncated reply: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 || length > maxMessage {
		return nil, fmt.Errorf("reply of %d bytes is not a Postgres message", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("truncated reply: %w", err)
	}
	return body, nil
}

// errorFields parses an ErrorResponse body: a run of (type byte, C string)
// pairs ended by a zero byte.
func errorFields(body []byte) map[byte]string {
	fields := map[byte]string{}
	for len(body) > 0 && body[0] != 0 {
		typ := body[0]
		rest := body[1:]
		end := len(rest)
		if i := strings.IndexByte(string(rest), 0); i >= 0 {
			end = i
		}
		fields[typ] = string(rest[:end])
		if end == len(rest) {
			break
		}
		body = rest[end+1:]
	}
	return fields
}

// errorMessage is the server's sentence from an ErrorResponse body, with its
// code, for a message a person reads.
func errorMessage(body []byte) string {
	f := errorFields(body)
	if f['M'] == "" {
		return "SQLSTATE " + f['C']
	}
	return fmt.Sprintf("%s (%s)", f['M'], f['C'])
}

// judgeError decides what an ErrorResponse to a startup message means.
//
// nil: the server is up and would take a session from somebody it knew. A
// *Refusal: the server said it cannot take one from anybody. Anything
// else: not a Postgres error message at all.
func judgeError(body []byte) error {
	f := errorFields(body)
	code := f['C']
	if code == "" {
		return errors.New("an error reply with no SQLSTATE; is this Postgres?")
	}
	// Class 57 is operator intervention: starting up, shutting down, in
	// recovery, cannot connect now. Class 53 is insufficient resources: too
	// many connections, out of memory, disk full. Every other class a startup
	// message can provoke -- 28 invalid authorization, 3D no such database,
	// 0A protocol version unsupported -- is the server turning this role
	// away, which is a working server.
	if strings.HasPrefix(code, "57") || strings.HasPrefix(code, "53") {
		return &Refusal{Code: code, Message: f['M']}
	}
	return nil
}

// ParsePostgresConnString reads the parts of a keyword/value connection string
// the handshake needs, and whether the string names a user.
//
// The user is how a stored string says which of the two Postgres checks it
// is. A check that signs in carries user, password and dbname; one that does
// not carries none of them, and there is no other difference. See
// checks.ParameterString, which is the only writer of these strings.
func ParsePostgresConnString(s string) (t PostgresTarget, signsIn bool) {
	kv := map[string]string{}
	for field := range strings.FieldsSeq(s) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		kv[strings.ToLower(key)] = value
	}
	_, signsIn = kv["user"]
	return PostgresTarget{Host: kv["host"], Port: kv["port"], SSLMode: kv["sslmode"]}, signsIn
}
