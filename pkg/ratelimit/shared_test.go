//go:build integration

package ratelimit

import (
	"os"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

// Against the compose Redis, or whatever GOWATCHER_TEST_REDIS names; skipped
// when none answers, as the database tests are without Postgres.
func testPool(t *testing.T) *redis.Pool {
	t.Helper()
	addr := os.Getenv("GOWATCHER_TEST_REDIS")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	pool := &redis.Pool{Dial: func() (redis.Conn, error) { return redis.Dial("tcp", addr) }}
	conn := pool.Get()
	defer conn.Close()
	if _, err := conn.Do("PING"); err != nil {
		t.Skipf("no Redis at %s: %v", addr, err)
	}
	return pool
}

func TestSharedCountsAcrossInstances(t *testing.T) {
	pool := testPool(t)
	name := "test-" + t.Name() + "-" + time.Now().Format("150405.000")
	var errs []error
	a := NewShared(pool, name, 3, 2*time.Second, func(err error) { errs = append(errs, err) })
	b := NewShared(pool, name, 3, 2*time.Second, nil) // a second replica
	key := "203.0.113.9"
	t.Cleanup(func() { a.Reset(key) })

	if !a.Allow(key) {
		t.Fatal("a fresh key is blocked")
	}
	a.Fail(key)
	b.Fail(key)
	if !b.Allow(key) || a.RetryAfter(key) != 0 {
		t.Fatal("blocked after two of three failures")
	}
	a.Fail(key)
	if b.Allow(key) {
		t.Fatal("the other replica still allows the key after the third failure")
	}
	if ra := b.RetryAfter(key); ra <= 0 || ra > 2*time.Second {
		t.Errorf("RetryAfter = %v, want within the window", ra)
	}
	b.Reset(key)
	if !a.Allow(key) {
		t.Fatal("a reset on one replica did not clear the other")
	}
	if len(errs) != 0 {
		t.Errorf("errors: %v", errs)
	}
}

func TestSharedWindowExpires(t *testing.T) {
	pool := testPool(t)
	s := NewShared(pool, "test-expiry-"+time.Now().Format("150405.000"), 1, 300*time.Millisecond, nil)
	s.Fail("k")
	if s.Allow("k") {
		t.Fatal("not blocked at the limit")
	}
	time.Sleep(400 * time.Millisecond)
	if !s.Allow("k") {
		t.Fatal("still blocked after the window")
	}
}
