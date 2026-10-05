//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

// On Linux the token is /etc/gryphon/agent_key, which the systemd unit hands
// the agent on standard input, and the settings /etc/gryphon/agent.env.
func enrolHere() (enrolPlace, error) {
	if os.Geteuid() != 0 {
		return enrolPlace{}, errors.New("enrolling writes /etc/gryphon: run it with sudo (sudo gryphon-agent enrol)")
	}
	return enrolPlace{
		tokenPath: "/etc/gryphon/agent_key",
		envPath:   "/etc/gryphon/agent.env",
		newline:   "\n",
		start:     startSystemdUnit,
		startHint: "sudo systemctl enable --now gryphon-agent",
	}, nil
}

// startSystemdUnit enables the unit, so it starts at boot, and restarts it,
// so an agent already running picks up the new token.
func startSystemdUnit() error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running here")
	}
	for _, args := range [][]string{{"enable", "gryphon-agent"}, {"restart", "gryphon-agent"}} {
		cmd := exec.Command("systemctl", args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
