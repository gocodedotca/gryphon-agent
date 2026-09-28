//go:build !unix && !windows

package clientagent

import (
	"context"
	"os"
	"os/exec"
)

// Without Unix permission bits or Windows ACLs there is nothing to judge here,
// and no process group to stop; the script itself is still stopped on time.
func unsafePermissions(string, os.FileInfo) string { return "" }

func executable(string, os.FileInfo) bool { return true }

const notExecutableHint = "it cannot be run"

func scriptCommand(ctx context.Context, path string) *exec.Cmd {
	return exec.CommandContext(ctx, path)
}

func runScript(cmd *exec.Cmd) error { return cmd.Run() }
