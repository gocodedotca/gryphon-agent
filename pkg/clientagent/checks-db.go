package clientagent

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gomodule/redigo/redis"
	"github.com/jackc/pgx/v5"
	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/netcheck"
	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

const dbTimeout = 10 * time.Second

// The database checks dial an address the server named, exactly as the network
// checks do -- "host" is a field on the form, and its default of 127.0.0.1 is
// only a default. So they go through the same reach; see reach.go.
//
// Each of the three drivers has to be told separately, because each opens its
// own sockets: pgx takes a DialFunc on its config, the MySQL driver dials by a
// network name registered with it, and redigo takes a DialOption. A driver
// left un-plumbed would be a way round the rule, which is why there is no
// generic sql.Open path here any more.

// checkPostgres signs in and pings when the connection string names a user,
// and otherwise asks the server, through its startup handshake, whether it is
// accepting connections at all. The second needs no role on the server; see
// netcheck.PostgresHandshake for what it proves and what it does not.
func (n *netProbe) checkPostgres(ctx context.Context, dsn string) result {
	if strings.TrimSpace(dsn) == "" {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("no connection string configured")}
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	if target, signsIn := netcheck.ParsePostgresConnString(dsn); !signsIn {
		rtt, err := netcheck.PostgresHandshake(ctx, n.dial, target)
		return n.handshakeResult("postgres", rtt, "", err)
	}

	cfg, err := pgx.ParseConfig(stripFileParams(dsn))
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("cannot read the postgres connection string: {err}", "err", err)}
	}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return n.dial(ctx, network, addr)
	}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		if netcheck.Blocked(err) {
			return refused()
		}
		return result{statusID: agent.StatusProblem, msg: cannotReach("postgres", err)}
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	if err := conn.Ping(ctx); err != nil {
		return result{statusID: agent.StatusProblem, msg: cannotReach("postgres", err)}
	}
	return result{statusID: agent.StatusHealthy, msg: phrase.T("pinged {db} successfully", "db", "postgres")}
}

// checkMariaDB is checkPostgres for the other engine: a DSN naming a user is
// signed in to and pinged; one naming none is answered by the server's
// greeting, which also says which version it is. See netcheck.MySQLHandshake.
func (n *netProbe) checkMariaDB(ctx context.Context, dsn string) result {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		// A DSN the driver cannot read is reported in the driver's own words,
		// the same as before this check had two modes.
		return result{statusID: agent.StatusProblem, msg: phrase.T("cannot open mariadb: {err}", "err", err)}
	}
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("cannot read the mariadb address: {err}", "err", err)}
	}

	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	if cfg.User == "" {
		g, err := netcheck.MySQLHandshake(ctx, n.dial, netcheck.MySQLTarget{Host: host, Port: port, TLS: cfg.TLSConfig})
		return n.handshakeResult("mariadb", g.RTT, g.Version, err)
	}

	// The driver dials by the name registered in the DSN, so the rule is
	// installed as a network of its own; see newNetProbe.
	cfg.Net = n.mysqlNetwork
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return result{statusID: agent.StatusProblem, msg: phrase.T("cannot open mariadb: {err}", "err", err)}
	}
	raw, err := conn.Connect(ctx)
	if err != nil {
		if netcheck.Blocked(err) {
			return refused()
		}
		return result{statusID: agent.StatusProblem, msg: cannotReach("mariadb", err)}
	}
	defer func() { _ = raw.Close() }()

	// A connection is not a session: the driver's own ping is what the
	// sql.Open path used to send, and what proves the server is serving.
	pinger, ok := raw.(driver.Pinger)
	if !ok {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("the mariadb driver cannot ping")}
	}
	if err := pinger.Ping(ctx); err != nil {
		return result{statusID: agent.StatusProblem, msg: cannotReach("mariadb", err)}
	}
	return result{statusID: agent.StatusHealthy, msg: phrase.T("pinged {db} successfully", "db", "mariadb")}
}

// handshakeResult turns a credential-free handshake into the agent's answer.
func (n *netProbe) handshakeResult(what string, rtt time.Duration, version string, err error) result {
	var refusal *netcheck.Refusal
	switch {
	case netcheck.Blocked(err):
		return refused()
	case errors.As(err, &refusal):
		// The server's own sentence: starting up, in recovery, out of
		// connections. It answered, so this is not "cannot reach".
		return result{statusID: agent.StatusProblem,
			msg: phrase.T("{db} is not accepting connections: {reason}", "db", what, "reason", refusal)}
	case err != nil:
		return result{statusID: agent.StatusProblem, msg: cannotReach(what, err)}
	}
	msg := phrase.T("{db} is accepting connections", "db", what)
	if version != "" {
		msg = phrase.T("{db} is accepting connections ({version})", "db", what, "version", version)
	}
	return result{statusID: agent.StatusHealthy, msg: msg, rtt: rtt}
}

// checkRedis pings redis at addr ("host:port", or a redis:// URL).
//
// The read and write timeouts matter as much as the connect one: a port that
// accepts the connection and never speaks Redis would otherwise hold PING open
// for as long as the connection lives.
func (n *netProbe) checkRedis(ctx context.Context, addr string) result {
	if strings.TrimSpace(addr) == "" {
		return result{statusID: agent.StatusUnknown, msg: phrase.T("no address configured")}
	}

	opts := []redis.DialOption{
		redis.DialNetDial(func(network, address string) (net.Conn, error) {
			return n.dial(ctx, network, address)
		}),
		redis.DialConnectTimeout(dbTimeout),
		redis.DialReadTimeout(dbTimeout),
		redis.DialWriteTimeout(dbTimeout),
	}

	var conn redis.Conn
	var err error
	if strings.Contains(addr, "://") {
		conn, err = redis.DialURLContext(ctx, addr, opts...)
	} else {
		conn, err = redis.DialContext(ctx, "tcp", addr, opts...)
	}
	if err != nil {
		if netcheck.Blocked(err) {
			return refused()
		}
		return result{statusID: agent.StatusProblem, msg: cannotReach("redis", err)}
	}
	defer conn.Close()

	// The old client called a successful TCP connect a healthy redis; PING is
	// what proves the server is actually serving.
	if _, err := redis.String(redis.DoContext(conn, ctx, "PING")); err != nil {
		return result{statusID: agent.StatusProblem, msg: phrase.T("redis did not answer PING: {err}", "err", err)}
	}
	return result{statusID: agent.StatusHealthy, msg: phrase.T("pinged {db} successfully", "db", "redis")}
}

// cannotReach is the message for a database the check could not get an
// answer from.
func cannotReach(db string, err error) string {
	return phrase.T("cannot reach {db}: {err}", "db", db, "err", err)
}

// registerMySQLNetwork installs this probe's dialer with the MySQL driver and
// returns the network name that reaches it.
//
// Registered once per probe and never removed: the driver's registry is global,
// and deregistering it around each check -- with one probe answering several at
// a time -- would take the dialer away from a connection still being made.
func (n *netProbe) registerMySQLNetwork() string {
	network := fmt.Sprintf("gwagent-%p", n)
	mysql.RegisterDialContext(network, func(ctx context.Context, addr string) (net.Conn, error) {
		return n.dial(ctx, "tcp", addr)
	})
	return network
}

// fileParams are the libpq settings that name a file on the machine the
// connection is made from. A connection string arrives from the server, so
// with these left in it a check could be made to open any file the agent
// can read -- a private key, a password file -- and report whether it
// parsed. None of them is a thing a monitoring check needs.
var fileParams = map[string]bool{
	"sslkey": true, "sslcert": true, "sslrootcert": true, "sslcrl": true, "sslcrldir": true,
	"sslpassword": true, "passfile": true, "service": true, "servicefile": true,
}

// stripFileParams removes fileParams from a postgres connection string, in
// either of its two shapes.
func stripFileParams(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		for k := range q {
			if fileParams[strings.ToLower(k)] {
				q.Del(k)
			}
		}
		u.RawQuery = q.Encode()
		return u.String()
	}
	var kept []string
	for _, pair := range strings.Fields(dsn) {
		k, _, _ := strings.Cut(pair, "=")
		if fileParams[strings.ToLower(k)] {
			continue
		}
		kept = append(kept, pair)
	}
	return strings.Join(kept, " ")
}
