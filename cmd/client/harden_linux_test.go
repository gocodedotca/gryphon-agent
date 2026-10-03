//go:build linux

package main

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// After hardenProcess, /proc/self belongs to root and the process cannot be
// traced by its own user: the scripts the agent runs cannot read its memory,
// environment or open files.
func TestHardenProcessMakesTheAgentNotDumpable(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatal(err)
	}
	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d after hardening, want 0", got)
	}
	if os.Getuid() != 0 {
		var st unix.Stat_t
		if err := unix.Stat("/proc/self/environ", &st); err == nil && st.Uid != 0 {
			t.Errorf("/proc/self/environ is owned by uid %d, want root", st.Uid)
		}
	}
}
