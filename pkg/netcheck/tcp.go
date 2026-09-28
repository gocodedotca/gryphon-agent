package netcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// The TCP checks: a service Gryphon has no check of its own for.
//
// Two questions, one probe. The port check asks whether anything accepts a
// connection. The send/expect check goes on to ask whether what answers is the
// thing somebody said it was: an SMTP server greets with "220", an SSH server
// with "SSH-", memcached answers "version" with "VERSION". A port that accepts
// connections and says the wrong thing -- a load balancer with nothing behind
// it, a different daemon on the port -- is the failure an open port hides.
//
// Deliberately one exchange and no more: a write, then a read until the
// expected bytes arrive. A scripted conversation is a protocol implementation
// written in a form field, and the protocols worth that already have checks.

// TLS modes for a TCP check.
const (
	// TLSNone speaks plain TCP.
	TLSNone = "none"
	// TLSVerify completes a TLS handshake first and verifies the certificate
	// against the address dialled.
	TLSVerify = "tls"
	// TLSNoVerify completes a TLS handshake and accepts any certificate, for an
	// internal service with a self-signed one.
	TLSNoVerify = "tls-no-verify"
)

// TLSModes are the TLS settings a TCP check accepts, in the order a form
// offers them.
var TLSModes = []string{TLSNone, TLSVerify, TLSNoVerify}

const (
	// MaxSend bounds what a check writes, after its escapes are decoded. A
	// probe is a line or two; anything longer is not a probe.
	MaxSend = 1024
	// MaxExpect bounds the text a response is searched for.
	MaxExpect = 256
	// MaxTCPRead is how much of a response is searched before giving up. A
	// greeting or a one-line reply is well inside it.
	MaxTCPRead = 4096
	// TCPTimeout bounds one probe, connecting included.
	TCPTimeout = 10 * time.Second

	// excerptLength bounds how much of a response a message quotes. Enough to
	// see that the wrong thing answered and what it was; not enough to make a
	// check a way of reading a service.
	excerptLength = 80
)

// tcpTimeout is TCPTimeout, as a variable so a test need not wait ten seconds
// to see a silent service reported.
var tcpTimeout = TCPTimeout

// TCPTarget is one TCP check's settings.
type TCPTarget struct {
	Host string
	Port string
	TLS  string
	// Send is written once connected. Expect is what the response must
	// contain; with none, the check is over once the connection (and any
	// write) succeeds.
	Send   []byte
	Expect []byte
}

// Address is host:port, as a message names it.
func (t TCPTarget) Address() string { return net.JoinHostPort(t.Host, t.Port) }

// ExpectError is a service that answered, but not with what was expected.
type ExpectError struct {
	// Got is what arrived, at most MaxTCPRead bytes of it.
	Got []byte
	// Why is how the read ended: the peer closed, the time ran out, or
	// MaxTCPRead arrived without a match.
	Why ExpectEnd
}

// ExpectEnd is how a read that did not find its text ended.
type ExpectEnd int

const (
	ExpectClosed ExpectEnd = iota
	ExpectTimedOut
	ExpectLimit
)

func (e *ExpectError) Error() string {
	switch e.Why {
	case ExpectTimedOut:
		return "the expected response did not arrive in time"
	case ExpectLimit:
		return "the expected response was not in the first 4 KB"
	}
	return "the connection closed without the expected response"
}

// ParseTCPParameters reads a TCP check's parameter string: a URL query string
// of agent.ParamHost, ParamPort, ParamTLS, ParamSend and ParamExpect, the last
// two with their escapes still written out.
func ParseTCPParameters(params string) (TCPTarget, error) {
	values, err := url.ParseQuery(params)
	if err != nil {
		return TCPTarget{}, err
	}
	t := TCPTarget{
		Host: NormalizeHost(values.Get(agent.ParamHost)),
		Port: strings.TrimSpace(values.Get(agent.ParamPort)),
		TLS:  strings.TrimSpace(values.Get(agent.ParamTLS)),
	}
	if t.TLS == "" {
		t.TLS = TLSNone
	}
	if err := ValidPort(t.Port); err != nil {
		return t, err
	}
	switch t.TLS {
	case TLSNone, TLSVerify, TLSNoVerify:
	default:
		return t, fmt.Errorf("%q is not a TLS setting", t.TLS)
	}
	if t.Send, err = DecodeEscapes(values.Get(agent.ParamSend)); err != nil {
		return t, fmt.Errorf("send: %w", err)
	}
	if t.Expect, err = DecodeEscapes(values.Get(agent.ParamExpect)); err != nil {
		return t, fmt.Errorf("expect: %w", err)
	}
	if len(t.Send) > MaxSend {
		return t, fmt.Errorf("send is %d bytes; the most a check sends is %d", len(t.Send), MaxSend)
	}
	if len(t.Expect) > MaxExpect {
		return t, fmt.Errorf("expect is %d bytes; the most a check looks for is %d", len(t.Expect), MaxExpect)
	}
	return t, nil
}

// ValidPort reports what is wrong with a port number, or nil.
func ValidPort(port string) error {
	n, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q is not a port number (1 to 65535)", port)
	}
	return nil
}

// DecodeEscapes turns the escapes a person can type into a one-line field into
// the bytes they stand for: \r, \n, \t, \0, \\ and \xHH. Anything else after a
// backslash is an error rather than a literal, so a typo is caught on save
// instead of being sent to a server that waits for a line ending forever.
func DecodeEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i == len(s) {
			return nil, errors.New(`a backslash at the end needs something after it (\\ for a backslash)`)
		}
		switch s[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(s) {
				return nil, errors.New(`\x needs two hex digits, as in \x1b`)
			}
			b, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, errors.New(`\x needs two hex digits, as in \x1b`)
			}
			out = append(out, byte(b))
			i += 2
		default:
			return nil, fmt.Errorf(`\%c is not an escape this check understands (\r \n \t \0 \\ \xHH)`, s[i])
		}
	}
	return out, nil
}

// TCPProbe connects to t, completes a TLS handshake if it asks for one, writes
// Send, and reads until Expect arrives. It reports how long that took.
//
// A nil error means the service answered as asked. An *ExpectError means it
// answered with something else. Any other error means it could not be reached
// or the handshake failed. dial may be nil for a plain net.Dialer; the server
// passes its outbound policy's. The probe takes at most TCPTimeout.
func TCPProbe(ctx context.Context, dial DialFunc, t TCPTarget) (time.Duration, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if strings.TrimSpace(t.Host) == "" {
		return 0, errors.New("no address to connect to")
	}

	probeCtx, cancel := context.WithTimeout(ctx, tcpTimeout)
	defer cancel()

	started := time.Now()
	raw, err := dial(probeCtx, "tcp", t.Address())
	if err != nil {
		return 0, err
	}
	defer func() { _ = raw.Close() }()
	// The probe's own time limit, and only that, as the socket's deadline. A
	// check cut short from outside arrives through the context instead: were
	// its earlier deadline set here too, the socket could report the timeout
	// a moment before the context says it has ended, and TCPOutcome would
	// call a cancelled check a silent service.
	_ = raw.SetDeadline(started.Add(tcpTimeout))
	stop := context.AfterFunc(probeCtx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	conn := raw
	if t.TLS == TLSVerify || t.TLS == TLSNoVerify {
		secured := tls.Client(raw, &tls.Config{
			// An address as well as a name: crypto/tls verifies an IP
			// against the certificate's IP SANs and sends no SNI for it.
			ServerName:         strings.Trim(t.Host, "[]"),
			InsecureSkipVerify: t.TLS == TLSNoVerify, //nolint:gosec // asked for, for self-signed internal services
			MinVersion:         tls.VersionTLS12,
		})
		if err := secured.HandshakeContext(probeCtx); err != nil {
			return 0, &TLSError{Err: err}
		}
		conn = secured
	}

	if len(t.Send) > 0 {
		if _, err := conn.Write(t.Send); err != nil {
			return 0, fmt.Errorf("cannot send: %w", err)
		}
	}
	if len(t.Expect) == 0 {
		return time.Since(started), nil
	}

	buf := make([]byte, 0, 512)
	chunk := make([]byte, 512)
	for {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if len(buf) > MaxTCPRead {
			buf = buf[:MaxTCPRead]
		}
		if bytes.Contains(buf, t.Expect) {
			return time.Since(started), nil
		}
		if len(buf) >= MaxTCPRead {
			return 0, &ExpectError{Got: buf, Why: ExpectLimit}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, &ExpectError{Got: buf, Why: ExpectTimedOut}
			}
			// EOF, or a reset after the peer said its piece: either way
			// nothing more is coming.
			return 0, &ExpectError{Got: buf, Why: ExpectClosed}
		}
	}
}

// TLSError is a TLS handshake that failed: the port answered, and not with a
// certificate this check accepts or with TLS at all.
type TLSError struct{ Err error }

func (e *TLSError) Error() string { return "TLS handshake failed: " + e.Err.Error() }
func (e *TLSError) Unwrap() error { return e.Err }

// TCPOutcome judges a probe. ctx is the one the probe ran under: when it has
// ended, the check was cut short from outside, which says nothing about the
// service.
//
// Everything that is the service's doing is a problem -- refused, reset, silent
// past the timeout, the wrong response, a certificate that does not verify.
// Only a resolver that is not answering, and a check cancelled from outside,
// are unknown.
func TCPOutcome(ctx context.Context, t TCPTarget, rtt time.Duration, err error) Outcome {
	addr := t.Address()
	if err == nil {
		if len(t.Expect) > 0 {
			return Outcome{
				Status:  agent.StatusHealthy,
				Message: fmt.Sprintf("%s - answered with %q in %s", addr, t.Expect, RoundRTT(rtt)),
				RTT:     rtt,
			}
		}
		return Outcome{
			Status:  agent.StatusHealthy,
			Message: fmt.Sprintf("%s - accepting connections, connected in %s", addr, RoundRTT(rtt)),
			RTT:     rtt,
		}
	}
	if ctx.Err() != nil {
		return unknown("%s - check cancelled or timed out", addr)
	}

	var expectErr *ExpectError
	if errors.As(err, &expectErr) {
		got := "nothing"
		if len(expectErr.Got) > 0 {
			got = Excerpt(expectErr.Got)
		}
		switch expectErr.Why {
		case ExpectTimedOut:
			return problem("%s - did not answer with %q within %s; got %s", addr, t.Expect, tcpTimeout, got)
		case ExpectLimit:
			return problem("%s - %q was not in the first 4 KB of the response; got %s", addr, t.Expect, got)
		}
		return problem("%s - closed the connection without answering %q; got %s", addr, t.Expect, got)
	}

	var tlsErr *TLSError
	if errors.As(err, &tlsErr) {
		var unknownAuthority x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthority) {
			return problem("%s - %v (for a self-signed certificate, choose %s)", addr, err, TLSNoVerify)
		}
		return problem("%s - %v", addr, err)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return problem("%s - name does not resolve", addr)
		}
		if dnsErr.IsTemporary || dnsErr.IsTimeout {
			return unknown("%s - name server did not answer: %v", addr, err)
		}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return problem("%s - connection refused", addr)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return problem("%s - did not accept a connection within %s", addr, tcpTimeout)
	}
	return problem("%s - %v", addr, err)
}

// Excerpt quotes the front of a response for a message: printable ASCII as it
// is, line endings and tabs as the escapes a person would type to match them,
// everything else as \xHH, cut at excerptLength characters.
func Excerpt(b []byte) string {
	var s strings.Builder
	s.WriteByte('"')
	written := 0
	for _, c := range b {
		var piece string
		switch {
		case c == '\r':
			piece = `\r`
		case c == '\n':
			piece = `\n`
		case c == '\t':
			piece = `\t`
		case c == '"' || c == '\\':
			piece = `\` + string(c)
		case c >= 0x20 && c <= 0x7e:
			piece = string(c)
		default:
			piece = fmt.Sprintf(`\x%02x`, c)
		}
		if written+len(piece) > excerptLength {
			s.WriteString(`"…`)
			return s.String()
		}
		s.WriteString(piece)
		written += len(piece)
	}
	s.WriteByte('"')
	return s.String()
}
