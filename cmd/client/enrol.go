package main

// `gryphon-agent enrol` gives the agent its token.
//
// Gryphon issues a token for each host and shows it once, on the host's page,
// with this command beside it. Enrolling asks for the token without echoing
// it, checks it by connecting to Gryphon once, saves it where the service
// reads it -- readable by administrators alone -- and starts the agent. A
// token copied short, or replaced since, is refused here, while the person
// who pasted it is still at the prompt, rather than in a log afterwards.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/gocodedotca/gryphon-agent/pkg/clientagent"
	"github.com/gocodedotca/gryphon-agent/pkg/envconf"
)

// enrolPlace is where this system keeps the agent's token and settings, and
// how it starts the agent; see enrol_linux.go, enrol_windows.go.
type enrolPlace struct {
	tokenPath string
	envPath   string
	// newline is how agent.env's lines end: "\r\n" on Windows, which
	// Notepad would otherwise show as one long line.
	newline string
	// start starts the agent, or restarts it if it is running.
	start func() error
	// startHint says how to start it by hand, for -no-start.
	startHint string
}

// enrolTimeout bounds the check of the token against Gryphon.
const enrolTimeout = 30 * time.Second

func enrolCommand(args []string) int {
	fs := flag.NewFlagSet("gryphon-agent enrol", flag.ContinueOnError)
	server := fs.String("server", "", "the Gryphon to connect to, when it is not "+clientagent.DefaultServer)
	insecure := fs.Bool("allow-insecure-server", false,
		"allow an http:// server: for development, or an installation reached only across its own network")
	noStart := fs.Bool("no-start", false, "save the token without starting the agent")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: gryphon-agent enrol [-server URL] [-no-start]")
		fmt.Fprintln(fs.Output(), "Asks for the token from the host's page in Gryphon, checks it, saves it and starts the agent.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	place, err := enrolHere()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// What agent.env already says, for a server set by an earlier enrol.
	current, err := envconf.ParseEnvFile(place.envPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	target := strings.TrimSpace(*server)
	if target == "" {
		target = current["GWC_SERVER"]
	}
	allowInsecure := *insecure || strings.EqualFold(current["GWC_ALLOW_INSECURE_SERVER"], "true")

	token, err := readToken(os.Stdin, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading the token:", err)
		return 1
	}
	if err := clientagent.ValidateKey(token); err != nil {
		fmt.Fprintf(os.Stderr, "That is not a token (%v). Copy it whole from the host's page in Gryphon.\n", err)
		return 1
	}

	cfg := clientagent.Config{Key: token, Server: target, AllowInsecureServer: allowInsecure}
	shown := target
	if shown == "" {
		shown = clientagent.DefaultServer
	}
	fmt.Fprintf(os.Stderr, "Checking the token with %s...\n", shown)
	ctx, cancel := context.WithTimeout(context.Background(), enrolTimeout)
	err = clientagent.Verify(ctx, cfg)
	cancel()
	switch {
	case errors.Is(err, clientagent.ErrTokenRefused):
		fmt.Fprintln(os.Stderr, "Gryphon refused this token. Check it was copied whole, and that it has not been replaced since; the host's page can issue a new one.")
		return 1
	case errors.Is(err, clientagent.ErrIncompatible):
		fmt.Fprintln(os.Stderr, "This Gryphon needs a newer agent. Install the latest release, then enrol again.")
		return 1
	case err != nil:
		fmt.Fprintf(os.Stderr, "Cannot reach Gryphon at %s: %v\n", shown, err)
		return 1
	}

	if err := writeSecret(place.tokenPath, token+place.newline); err != nil {
		fmt.Fprintln(os.Stderr, "saving the token:", err)
		return 1
	}
	if *server != "" {
		if err := setEnvVar(place.envPath, "GWC_SERVER", strings.TrimSpace(*server), place.newline); err != nil {
			fmt.Fprintln(os.Stderr, "saving the server:", err)
			return 1
		}
	}
	if *insecure {
		if err := setEnvVar(place.envPath, "GWC_ALLOW_INSECURE_SERVER", "true", place.newline); err != nil {
			fmt.Fprintln(os.Stderr, "saving the setting:", err)
			return 1
		}
	}
	fmt.Fprintln(os.Stderr, "The token is good, and saved in "+place.tokenPath+".")

	if *noStart {
		fmt.Fprintln(os.Stderr, "Start the agent when you are ready: "+place.startHint)
		return 0
	}
	if err := place.start(); err != nil {
		fmt.Fprintln(os.Stderr, "starting the agent:", err)
		fmt.Fprintln(os.Stderr, "Start it yourself: "+place.startHint)
		return 1
	}
	fmt.Fprintln(os.Stderr, "The agent is running. The host's page in Gryphon shows it connected within a few seconds.")
	return 0
}

// readToken asks for the token. At a terminal it is not echoed, so it does
// not end up in a screen recording or over a shoulder; piped in, the first
// line is read.
func readToken(in *os.File, prompt io.Writer) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return readKeyFrom(in)
	}
	fmt.Fprint(prompt, "Paste the token from the host's page in Gryphon (it is not shown as you paste): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// writeSecret writes value to path readable by its owner alone, beside it
// and renamed over it, so a failure halfway leaves the old token rather
// than half of the new one.
func writeSecret(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// setEnvVar sets one variable in an env file, keeping everything else in it:
// a line that sets it already is replaced, else the commented-out example of
// it, else the variable is added at the end. A missing file is made.
func setEnvVar(path, name, value, newline string) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
	}

	set := name + "=" + value
	replaced := false
	for _, commented := range []bool{false, true} {
		for i, line := range lines {
			l := strings.TrimSpace(line)
			if commented {
				if !strings.HasPrefix(l, "#") {
					continue
				}
				l = strings.TrimSpace(strings.TrimPrefix(l, "#"))
			}
			if strings.HasPrefix(l, name+"=") {
				lines[i] = set
				replaced = true
				break
			}
		}
		if replaced {
			break
		}
	}
	if !replaced {
		lines = append(lines, set)
	}
	return writeSecret(path, strings.Join(lines, newline)+newline)
}
