// Package ratelimit counts failed attempts per key and blocks a key that
// exceeds a threshold within a window.
//
// Two implementations of one shape: Memory, for a single process and for
// tests, and Shared, on Redis, which is what a deployment with more than one
// replica uses so that every replica sees the same count. See shared.go.
package ratelimit

import (
	"sync"
	"time"
)

// sweepThreshold is how many keys may accumulate before expired ones are
// cleared out, so a stream of distinct keys cannot grow the map without bound.
const sweepThreshold = 1024

type entry struct {
	count   int
	resetAt time.Time
}

// Memory counts failed attempts in this process only.
type Memory struct {
	mu      sync.Mutex
	entries map[string]*entry
	max     int
	window  time.Duration
	now     func() time.Time
}

// New returns an in-memory limiter allowing max failures per key within window.
func New(max int, window time.Duration) *Memory {
	return &Memory{
		entries: make(map[string]*entry),
		max:     max,
		window:  window,
		now:     time.Now,
	}
}

// Allow reports whether an attempt for key may proceed. It does not record
// anything: call Fail after an attempt that failed, or Reset after one that
// succeeded.
func (l *Memory) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		return true
	}
	if l.now().After(e.resetAt) {
		delete(l.entries, key)
		return true
	}
	return e.count < l.max
}

// RetryAfter returns how long the caller should wait before key is allowed
// again. It is zero when the key is not currently blocked.
func (l *Memory) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok || e.count < l.max {
		return 0
	}
	remaining := e.resetAt.Sub(l.now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Fail records one failed attempt for key.
func (l *Memory) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.entries) >= sweepThreshold {
		l.sweepLocked(now)
	}

	e, ok := l.entries[key]
	if !ok || now.After(e.resetAt) {
		l.entries[key] = &entry{count: 1, resetAt: now.Add(l.window)}
		return
	}
	e.count++
}

// Reset clears the record for key, which a caller does after a success.
func (l *Memory) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *Memory) sweepLocked(now time.Time) {
	for k, e := range l.entries {
		if now.After(e.resetAt) {
			delete(l.entries, k)
		}
	}
}
