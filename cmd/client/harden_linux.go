//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// hardenProcess makes the agent a process its own user cannot look into.
//
// Script checks run as the agent's user, and an ordinary process may read the
// memory, environment and open files of another process of the same user
// through /proc and ptrace. The agent holds its access key in memory, and
// may have it in its environment (GWC_KEY) or have been handed it on a file
// descriptor, so without this any script -- or anything a script runs, such
// as a plugin's dependencies -- could read the key out of the agent.
// Marking the process not dumpable makes /proc/<pid> root's and refuses
// ptrace to anyone without CAP_SYS_PTRACE; the scripts the agent starts get
// neither, since they are separate processes started by exec.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// releaseStdin points standard input at /dev/null once the key has been read
// from it, so the file systemd opened is closed for good.
func releaseStdin() error {
	null, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer null.Close()
	return unix.Dup2(int(null.Fd()), 0)
}
