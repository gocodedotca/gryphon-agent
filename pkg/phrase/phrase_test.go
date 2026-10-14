package phrase

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestT(t *testing.T) {
	got := T("{host} - responded to ping in {rtt}, {n} of {total}", "host", "example.com",
		"rtt", 4100*time.Microsecond, "n", 3, "total", int64(4))
	if want := "example.com - responded to ping in 4.1ms, 3 of 4"; got != want {
		t.Errorf("T = %q, want %q", got, want)
	}
	if got := T("no {value} for this one"); got != "no {value} for this one" {
		t.Errorf("T with no values changed the format: %q", got)
	}
}

func TestErrorf(t *testing.T) {
	err := Errorf("no greeting: {err}", "err", io.EOF)
	if err.Error() != "no greeting: EOF" {
		t.Errorf("Errorf = %q", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Error("Errorf does not wrap the error it was given")
	}
}
