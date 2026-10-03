//go:build !linux

package main

// hardenProcess has nothing to do here. On Windows a script runs as the
// service's account and can read what the service can; see the agent
// README's section on scripts. On macOS the agent is the signed-in user's
// own app, running that user's own scripts.
func hardenProcess() error { return nil }

// releaseStdin has nothing to close: GWC_KEY_FILE=- is for a service manager
// that opens the key file for the agent, which is systemd's.
func releaseStdin() error { return nil }
