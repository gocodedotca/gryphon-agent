package ratelimit

import (
	"testing"
	"time"
)

func TestAllowsUntilThreshold(t *testing.T) {
	l := New(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d was blocked; the threshold is 3", i+1)
		}
		l.Fail("k")
	}

	if l.Allow("k") {
		t.Error("a fourth attempt was allowed after 3 failures")
	}
}

func TestSuccessClearsTheCount(t *testing.T) {
	l := New(3, time.Minute)
	l.Fail("k")
	l.Fail("k")
	l.Reset("k")

	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d blocked after a reset", i+1)
		}
		l.Fail("k")
	}
}

func TestWindowExpires(t *testing.T) {
	l := New(2, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }

	l.Fail("k")
	l.Fail("k")
	if l.Allow("k") {
		t.Fatal("expected to be blocked at the threshold")
	}

	now = now.Add(61 * time.Second)
	if !l.Allow("k") {
		t.Error("still blocked after the window expired")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, time.Minute)
	l.Fail("a")

	if l.Allow("a") {
		t.Error("key a should be blocked")
	}
	if !l.Allow("b") {
		t.Error("key b was blocked by key a's failures")
	}
}

func TestRetryAfter(t *testing.T) {
	l := New(1, 10*time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }

	if d := l.RetryAfter("k"); d != 0 {
		t.Errorf("RetryAfter on an unknown key = %v, want 0", d)
	}

	l.Fail("k")
	if d := l.RetryAfter("k"); d <= 0 || d > 10*time.Minute {
		t.Errorf("RetryAfter = %v, want between 0 and 10m", d)
	}
}

func TestSweepBoundsMemory(t *testing.T) {
	l := New(5, time.Millisecond)
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := 0; i < sweepThreshold; i++ {
		l.Fail(string(rune(i)) + "x")
	}
	now = now.Add(time.Second) // everything is now expired
	l.Fail("trigger-the-sweep")

	l.mu.Lock()
	size := len(l.entries)
	l.mu.Unlock()

	if size > 1 {
		t.Errorf("after a sweep the map holds %d entries, want 1", size)
	}
}
