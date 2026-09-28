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

// The MariaDB/MySQL check that does not sign in.
//
// A MySQL-family server speaks first. The moment a connection opens it sends a
// greeting naming its version, its capabilities and the authentication plugin
// it wants, all before the client has said a word. That greeting is most of
// what this check wants to know: the server is up, it is MySQL, and this is
// the version. A server that cannot serve sends an error instead of a greeting
// -- "Too many connections" is the usual one -- which is the other thing this
// check wants to know.
//
// The greeting alone would do, but stopping there has a cost on the server:
// a connection dropped before the handshake completes is a "handshake error",
// and after max_connect_errors of those in a row from one address (a hundred,
// by default) the server blocks that address for good. A monitor probing every
// few minutes would block itself within a day. So the handshake is finished
// rather than abandoned: the probe answers the greeting as a role that does
// not exist, with an empty password, and the server refuses it. A refused
// password is an authentication error, which does not count towards blocking.
// The empty password matters: given one, every plugin either accepts the
// account outright or refuses it at once, so there is no further exchange to
// complete -- which is what keeps this free of the scrambling and public-key
// business the plugins otherwise involve.
//
// What the server sees is one refused sign-in per check. MariaDB writes a
// warning for it at its default log level ("Access denied for user
// 'gryphon_probe'"), as it also does for an abandoned handshake; MySQL 8.4
// writes a deprecation warning about sha256_password for any sign-in by an
// unknown user, this one included. Neither is avoidable from this side, and
// both name the probe role, so an operator can see what they are.
//
// TLS is honoured as the DSN's tls parameter has it: false is plaintext, true
// negotiates TLS and verifies the certificate as the driver would, preferred
// negotiates it without verifying when the server offers it and goes without
// when it does not.

// MySQLTarget is what the handshake needs to know: where, and whether to speak
// TLS.
type MySQLTarget struct {
	Host string
	// Port defaults to 3306.
	Port string
	// TLS is the DSN's tls parameter in the driver's vocabulary: false, true
	// or preferred. skip-verify is read as preferred; anything else as false.
	TLS string
}

// MySQLGreeting is what a server said about itself before anybody signed in.
type MySQLGreeting struct {
	// Version is the server's version string as it sent it, less the
	// "5.5.5-" MariaDB prefixes for the sake of old clients. Empty when the
	// server refused the connection before greeting it.
	Version string
	RTT     time.Duration
}

// MySQLHandshake asks a MariaDB or MySQL server whether it would accept a
// session, without signing in.
//
// A nil error means the server is accepting connections, and the greeting
// carries its version. A *Refusal means the server answered that it is not.
// Any other error means the target could not be reached, hung up, or did not
// speak the MySQL protocol.
func MySQLHandshake(ctx context.Context, dial DialFunc, t MySQLTarget) (MySQLGreeting, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	port := strings.TrimSpace(t.Port)
	if port == "" {
		port = "3306"
	}
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return MySQLGreeting{}, errors.New("no address to connect to")
	}

	started := time.Now()
	raw, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return MySQLGreeting{}, err
	}
	defer func() { _ = raw.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}

	seq, payload, err := readMySQLPacket(raw)
	if err != nil {
		return MySQLGreeting{}, fmt.Errorf("no greeting: %w", err)
	}
	if len(payload) > 0 && payload[0] == mysqlErr {
		// Refused before being greeted: too many connections, or this
		// address is not allowed. Either way it is a MySQL server speaking.
		return MySQLGreeting{RTT: time.Since(started)}, judgeMySQLError(payload)
	}
	g, err := parseMySQLGreeting(payload)
	if err != nil {
		return MySQLGreeting{}, err
	}
	greeting := MySQLGreeting{Version: g.version}

	conn := raw
	mode := strings.ToLower(strings.TrimSpace(t.TLS))
	useTLS := false
	switch mode {
	case "true", "skip-verify", "preferred":
		if g.capabilities&clientSSL != 0 {
			useTLS = true
		} else if mode != "preferred" {
			return greeting, errors.New("the server does not support TLS, and the check requires it")
		}
	}

	// The capabilities this client claims: the modern protocol, the secure
	// authentication packet, and a named plugin, each only if the server has
	// them too. Never a database, so nothing has to exist on the server.
	caps := (clientProtocol41 | clientSecureConnection | clientPluginAuth | clientLongPassword) & g.capabilities
	if useTLS {
		caps |= clientSSL
		seq++
		if err := writeMySQLPacket(conn, seq, mysqlHandshakePrefix(caps, g.charset)); err != nil {
			return greeting, fmt.Errorf("cannot send an SSL request: %w", err)
		}
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:         serverName(host),
			InsecureSkipVerify: mode != "true", //nolint:gosec // preferred and skip-verify are the driver's own no-verify modes
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return greeting, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// The handshake response: the prefix again, then the probe role, an
	// empty password, and the plugin the server asked for.
	resp := mysqlHandshakePrefix(caps, g.charset)
	resp = append(resp, probeRole...)
	resp = append(resp, 0)
	resp = append(resp, 0) // an empty auth response, length-prefixed
	if caps&clientPluginAuth != 0 {
		plugin := g.authPlugin
		if plugin == "" {
			plugin = "mysql_native_password"
		}
		resp = append(resp, plugin...)
		resp = append(resp, 0)
	}
	seq++
	if err := writeMySQLPacket(conn, seq, resp); err != nil {
		return greeting, fmt.Errorf("cannot answer the greeting: %w", err)
	}

	// The server's verdict. An empty password is settled in one reply for
	// every plugin: OK, or an error. A plugin switch or a request for more
	// data is answered with another empty packet, a few times at most, for a
	// server configured with something exotic.
	for round := 0; round < 4; round++ {
		var reply []byte
		seq, reply, err = readMySQLPacket(conn)
		if err != nil {
			return greeting, fmt.Errorf("no answer to the handshake: %w", err)
		}
		greeting.RTT = time.Since(started)
		if len(reply) == 0 {
			return greeting, errors.New("an empty reply to the handshake; is this MySQL?")
		}
		switch reply[0] {
		case mysqlErr:
			// Access denied for the probe role is the expected answer, and
			// it is a server consulting its grant tables: healthy. The few
			// codes that say the server cannot serve are the exception.
			return greeting, judgeMySQLError(reply)
		case mysqlOK:
			return greeting, nil
		case mysqlAuthSwitch, mysqlAuthMoreData:
			seq++
			if err := writeMySQLPacket(conn, seq, nil); err != nil {
				return greeting, fmt.Errorf("cannot answer an authentication request: %w", err)
			}
		default:
			return greeting, fmt.Errorf("unexpected reply %#x to the handshake; is this MySQL?", reply[0])
		}
	}
	return greeting, errors.New("the server kept asking for authentication data")
}

// The MySQL client/server protocol, as much of it as the handshake touches.
const (
	clientLongPassword     = 0x00000001
	clientProtocol41       = 0x00000200
	clientSSL              = 0x00000800
	clientSecureConnection = 0x00008000
	clientPluginAuth       = 0x00080000

	mysqlOK           = 0x00
	mysqlAuthMoreData = 0x01
	mysqlAuthSwitch   = 0xFE
	mysqlErr          = 0xFF
)

// mysqlHandshakePrefix is the fixed 32 bytes that begin both the SSL request
// and the handshake response: capabilities, maximum packet size, character
// set, and 23 reserved bytes.
func mysqlHandshakePrefix(caps uint32, charset byte) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:4], caps)
	binary.LittleEndian.PutUint32(b[4:8], 1<<24-1)
	b[8] = charset
	return b
}

// readMySQLPacket reads one packet: a three-byte little-endian length, a
// sequence number, and the payload.
func readMySQLPacket(conn net.Conn) (seq byte, payload []byte, err error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > maxMessage {
		return 0, nil, fmt.Errorf("a packet of %d bytes is not a MySQL greeting", length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, fmt.Errorf("truncated packet: %w", err)
	}
	return header[3], payload, nil
}

// writeMySQLPacket sends one packet. A nil payload is a legal empty packet,
// which is how an empty password is sent.
func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	msg := make([]byte, 4, 4+len(payload))
	msg[0] = byte(len(payload))
	msg[1] = byte(len(payload) >> 8)
	msg[2] = byte(len(payload) >> 16)
	msg[3] = seq
	msg = append(msg, payload...)
	_, err := conn.Write(msg)
	return err
}

// mysqlGreeting is the initial handshake packet, protocol version 10.
type mysqlGreeting struct {
	version      string
	capabilities uint32
	charset      byte
	authPlugin   string
}

// parseMySQLGreeting reads the parts of the greeting the handshake needs.
//
// Everything after the lower capability flags is optional in the protocol,
// and a short packet is read as far as it goes rather than refused: it is the
// server's version and its capabilities that matter, and both come early.
func parseMySQLGreeting(p []byte) (mysqlGreeting, error) {
	var g mysqlGreeting
	if len(p) < 1 || p[0] != 10 {
		return g, errors.New("the greeting is not MySQL protocol version 10; is this MySQL?")
	}
	end := strings.IndexByte(string(p[1:]), 0)
	if end < 0 {
		return g, errors.New("the greeting names no server version; is this MySQL?")
	}
	g.version = strings.TrimPrefix(string(p[1:1+end]), "5.5.5-")
	pos := 1 + end + 1
	pos += 4 // connection id
	pos += 8 // the first part of the authentication data
	pos++    // filler
	if len(p) < pos+2 {
		return g, errors.New("the greeting is truncated; is this MySQL?")
	}
	g.capabilities = uint32(binary.LittleEndian.Uint16(p[pos : pos+2]))
	pos += 2
	if len(p) < pos+1+2+2 {
		return g, nil
	}
	g.charset = p[pos]
	pos++
	pos += 2 // status flags
	g.capabilities |= uint32(binary.LittleEndian.Uint16(p[pos:pos+2])) << 16
	pos += 2
	if len(p) < pos+1 {
		return g, nil
	}
	authLen := int(p[pos])
	pos++
	pos += 10 // reserved
	// The second part of the authentication data: at least 13 bytes, or as
	// many as the declared length leaves after the first eight.
	part2 := 13
	if authLen-8 > part2 {
		part2 = authLen - 8
	}
	pos += part2
	if g.capabilities&clientPluginAuth != 0 && len(p) > pos {
		rest := string(p[pos:])
		if i := strings.IndexByte(rest, 0); i >= 0 {
			rest = rest[:i]
		}
		g.authPlugin = rest
	}
	return g, nil
}

// judgeMySQLError decides what an error packet means.
//
// nil: the server is up and turned the probe role away, which is a working
// server. A *Refusal: the server said it cannot take a session from anybody.
// Anything else: not a MySQL error packet at all.
func judgeMySQLError(p []byte) error {
	if len(p) < 3 || p[0] != mysqlErr {
		return errors.New("a malformed error packet; is this MySQL?")
	}
	code := binary.LittleEndian.Uint16(p[1:3])
	msg := p[3:]
	// Protocol 4.1 puts "#" and a five-character SQLSTATE before the text.
	if len(msg) >= 6 && msg[0] == '#' {
		msg = msg[6:]
	}
	switch code {
	case 1040, // ER_CON_COUNT_ERROR: Too many connections
		1053: // ER_SERVER_SHUTDOWN: Server shutdown in progress
		return &Refusal{Code: fmt.Sprint(code), Message: string(msg)}
	}
	// 1045 access denied is the expected reply to the probe role. 1130
	// (this host is not allowed to connect) and 1129 (this host is blocked)
	// are the server's access rules, about us rather than about it, and
	// 3159 (insecure transport prohibited) is a server that wanted TLS the
	// check was not told to use. All of them are a server that is serving.
	return nil
}
