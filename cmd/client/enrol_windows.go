//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
)

// On Windows the token is agent_key in C:\ProgramData\Gryphon, which
// service install made readable by administrators and the service alone,
// and the settings agent.env beside it.
func enrolHere() (enrolPlace, error) {
	m, err := connect()
	if err != nil {
		return enrolPlace{}, err
	}
	s, err := m.OpenService(serviceName)
	m.Disconnect()
	if err != nil {
		return enrolPlace{}, errors.New("the GryphonAgent service is not installed: run gryphon-agent.exe service install first")
	}
	s.Close()
	dir := dataDir()
	return enrolPlace{
		tokenPath: filepath.Join(dir, "agent_key"),
		envPath:   filepath.Join(dir, "agent.env"),
		newline:   "\r\n",
		start:     restartService,
		startHint: "Start-Service GryphonAgent",
	}, nil
}

// restartService starts the service, stopping it first if it is running so
// it reads the new token.
func restartService() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if err := stopService(s); err != nil {
			return err
		}
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("starting the service: %w", err)
	}
	return nil
}
