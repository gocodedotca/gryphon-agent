//go:build !unix

package clientagent

import (
	"os"
	"os/exec"
)

// Without Unix permission bits there is nothing to judge here, and no process
// group to stop; the script itself is still stopped on time.
func unsafePermissions(os.FileInfo) string { return "" }

func executable(os.FileInfo) bool { return true }

func stopWholeGroup(*exec.Cmd) {}
