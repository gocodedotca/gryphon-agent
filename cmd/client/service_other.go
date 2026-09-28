//go:build !windows

package main

import (
	"fmt"
	"os"
)

// The service command and the service manager are Windows'. On Linux the
// packages install a systemd unit, deploy/agent/gryphon-agent.service.

func isService() bool { return false }

func runService() {}

func serviceCommand([]string) int {
	fmt.Fprintln(os.Stderr, "the service command is for Windows; on Linux the .deb and .rpm install the systemd unit gryphon-agent.service")
	return 2
}
