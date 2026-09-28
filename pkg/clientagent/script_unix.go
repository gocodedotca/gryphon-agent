//go:build unix

package clientagent

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// unsafePermissions says why a script or its directory must not be trusted,
// or "". Anything another user on the machine can write to is something
// another user on the machine can make the agent run, so: not world-writable,
// not writable by a group the agent is not in, and owned by root or by the
// agent's own user -- a file somebody else owns is a file somebody else can
// rewrite whatever its mode says today.
func unsafePermissions(info os.FileInfo) string {
	mode := info.Mode().Perm()
	if mode&0o002 != 0 {
		return "is writable by every user on this machine"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Getuid() {
		return fmt.Sprintf("is owned by uid %d, not root or the agent's user", uid)
	}
	if mode&0o020 != 0 && int(st.Gid) != os.Getgid() && !inGroup(int(st.Gid)) {
		return fmt.Sprintf("is writable by group %d, which the agent is not in", st.Gid)
	}
	return ""
}

// inGroup reports whether the agent's user is in gid, beyond its primary
// group.
func inGroup(gid int) bool {
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

func executable(info os.FileInfo) bool { return info.Mode().Perm()&0o111 != 0 }

// stopWholeGroup runs the script in a process group of its own and stops the
// whole group when the check's time is up, so that what a shell script
// started does not outlive it.
func stopWholeGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
