package ratelimit

import (
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
)

// Limiter is what the handlers hold: the in-memory Memory limiter, or a
// Shared one on Redis when the application runs more than one replica.
type Limiter interface {
	Allow(key string) bool
	RetryAfter(key string) time.Duration
	Fail(key string)
	Reset(key string)
}

// Shared counts failures in Redis, so every replica sees the same count.
//
// The in-memory limiter is per process: with two replicas behind a proxy a
// login attacker gets twice the attempts, and a lockout on one replica is
// invisible to the other. This keeps the same shape -- Allow, Fail, Reset,
// RetryAfter -- on a Redis counter with the window as its expiry. Redis is
// already a hard dependency (sessions, the live-update relay), so nothing
// new has to run.
//
// If Redis cannot be reached the limiter fails open and says so once: a
// dead Redis is already a dead session store, and locking everybody out on
// top of that helps nobody.
type Shared struct {
	pool   *redis.Pool
	prefix string
	max    int
	window time.Duration
	// onError is told about a Redis failure; nil means silent.
	onError func(error)
}

// NewShared returns a limiter on Redis allowing max failures per key within
// window. name distinguishes the limiters of one installation; the key of
// each ("login:203.0.113.9") hangs off it.
func NewShared(pool *redis.Pool, name string, max int, window time.Duration, onError func(error)) *Shared {
	return &Shared{pool: pool, prefix: "gowatcher:ratelimit:" + name + ":", max: max, window: window, onError: onError}
}

func (s *Shared) report(err error) {
	if s.onError != nil {
		s.onError(err)
	}
}

// Allow reports whether an attempt for key may proceed.
func (s *Shared) Allow(key string) bool {
	conn := s.pool.Get()
	defer conn.Close()
	n, err := redis.Int(conn.Do("GET", s.prefix+key))
	if err == redis.ErrNil {
		return true
	}
	if err != nil {
		s.report(err)
		return true
	}
	return n < s.max
}

// RetryAfter is how long key stays blocked, or zero when it is not.
func (s *Shared) RetryAfter(key string) time.Duration {
	conn := s.pool.Get()
	defer conn.Close()
	n, err := redis.Int(conn.Do("GET", s.prefix+key))
	if err != nil || n < s.max {
		if err != nil && err != redis.ErrNil {
			s.report(err)
		}
		return 0
	}
	ms, err := redis.Int64(conn.Do("PTTL", s.prefix+key))
	if err != nil || ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// Fail records one failed attempt for key. The window starts at the first
// failure and is not extended by later ones, as the in-memory limiter's is not.
func (s *Shared) Fail(key string) {
	conn := s.pool.Get()
	defer conn.Close()
	n, err := redis.Int64(conn.Do("INCR", s.prefix+key))
	if err != nil {
		s.report(err)
		return
	}
	if n == 1 {
		if _, err := conn.Do("PEXPIRE", s.prefix+key, strconv.FormatInt(s.window.Milliseconds(), 10)); err != nil {
			s.report(err)
		}
	}
}

// Reset forgets key, after an attempt that succeeded.
func (s *Shared) Reset(key string) {
	conn := s.pool.Get()
	defer conn.Close()
	if _, err := conn.Do("DEL", s.prefix+key); err != nil {
		s.report(err)
	}
}
