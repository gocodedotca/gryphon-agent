// Package envconf reads prefixed configuration out of the environment, for the
// server, the client agent and the vantage alike.
package envconf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Resolver reads configuration out of the environment, honouring the NAME_FILE
// convention that orchestrators use to deliver secrets.
//
// Docker and Kubernetes both mount secrets as files -- Docker Swarm at
// /run/secrets/<name> -- and neither can put one into a variable without a
// shell wrapper to read it back out. So every variable this application
// understands has a _FILE twin naming a file whose contents supply the value:
//
//	GOWATCHER_DB_PASSWORD_FILE=/run/secrets/db_password
//
// It applies to every variable and not merely the obviously secret ones,
// because which ones are secret is the operator's judgement, not ours: an
// installation that considers its Twilio number or its retention window
// sensitive should not have to discover that half the configuration accepts a
// file and the other half does not.
//
// Read errors are collected rather than returned one at a time, so a
// misconfigured deployment learns about all of its bad paths in one restart.
// Check Err once the values have been resolved.
type Resolver struct {
	prefix string
	getenv func(string) string
	err    error
}

// NewResolver returns a Resolver reading prefix-namespaced variables through
// getenv.
//
// getenv is passed in rather than read from the process so callers are
// testable without mutating global state.
func NewResolver(prefix string, getenv func(string) string) *Resolver {
	return &Resolver{prefix: prefix, getenv: getenv}
}

// Err reports the first file that could not be read, or nil.
//
// An unreadable _FILE is an error and not a fall-back to the default: the
// operator said where the secret lives, and starting up with a generated key
// or an empty password because a mount was missing is worse than not starting.
func (r *Resolver) Err() error { return r.err }

// Lookup resolves one variable. ok reports whether it was set at all, which
// is not the same as being non-empty: a _FILE pointing at an empty file
// deliberately clears the value.
func (r *Resolver) Lookup(name string) (value string, ok bool) {
	full := r.prefix + name
	if path := r.getenv(full + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			if r.err == nil {
				r.err = fmt.Errorf("settings: %s_FILE: %w", full, err)
			}
			return "", false
		}
		// A file written by a human, or by `echo`, ends in a newline that is
		// not part of the value.
		return strings.TrimSpace(string(b)), true
	}
	if v := r.getenv(full); v != "" {
		return v, true
	}
	return "", false
}

// String assigns the variable to target if it is set, leaving whatever was
// already there if it is not.
func (r *Resolver) String(name string, target *string) {
	if v, ok := r.Lookup(name); ok {
		*target = v
	}
}

// Bool parses "true"/"false" (and the rest of what strconv.ParseBool takes).
func (r *Resolver) Bool(name string, target *bool) {
	v, ok := r.Lookup(name)
	if !ok || v == "" {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.fail(name, err)
		return
	}
	*target = b
}

// Int parses a count.
func (r *Resolver) Int(name string, target *int) {
	v, ok := r.Lookup(name)
	if !ok || v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		r.fail(name, err)
		return
	}
	*target = n
}

// Duration parses a Go duration, e.g. 2s or 500ms.
func (r *Resolver) Duration(name string, target *time.Duration) {
	v, ok := r.Lookup(name)
	if !ok || v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		r.fail(name, err)
		return
	}
	*target = d
}

// fail records a parse failure against the variable's own name, so the message
// names what the operator has to go and fix.
func (r *Resolver) fail(name string, err error) {
	if r.err == nil {
		r.err = fmt.Errorf("settings: %s%s: %w", r.prefix, name, err)
	}
}
