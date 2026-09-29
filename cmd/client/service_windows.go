package main

// The agent as a Windows service.
//
// `gryphon-agent service install`, from an elevated prompt, does what the
// Linux package does: puts the program where only administrators can change
// it (C:\Program Files\Gryphon Agent), makes C:\ProgramData\Gryphon for its
// key and settings, readable by administrators and the service alone, makes an
// access key if there is none, and registers the service -- without starting
// it, so it does not listen before the host in Gryphon has the key. Run again
// from a newer build it is the update: it stops the service, replaces the
// program and starts it again if it was running.
//
// The service runs as the virtual account NT SERVICE\GryphonAgent: no
// password, no rights beyond an ordinary user's, the Windows counterpart of the
// systemd unit's DynamicUser. Its settings are C:\ProgramData\Gryphon\agent.env,
// the same GWC_* variables as on Linux, and its key agent_key beside it. It
// logs to the Application event log, as source GryphonAgent.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/gocodedotca/gryphon-agent/pkg/clientagent"
	"github.com/gocodedotca/gryphon-agent/pkg/envconf"
)

const (
	serviceName        = "GryphonAgent"
	serviceDisplayName = "Gryphon Agent"
	serviceAccount     = `NT SERVICE\` + serviceName
	serviceDescription = "Measures this machine for the Gryphon monitoring service."
	// serviceDefaultPort is loopback, as the Linux unit's is: the agent
	// belongs behind a reverse proxy with TLS.
	serviceDefaultPort = "127.0.0.1:6001"
	programName        = "gryphon-agent.exe"
)

// dataDir is C:\ProgramData\Gryphon, or wherever ProgramData is.
func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Gryphon")
}

// programDir is C:\Program Files\Gryphon Agent, or wherever Program Files is.
func programDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, serviceDisplayName)
}

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// serviceGetenv is the environment the service reads its settings from: its
// own environment first, then agent.env, then the service's defaults -- the
// key file beside agent.env, and loopback.
func serviceGetenv() (func(string) string, error) {
	dir := dataDir()
	vars, err := envconf.ParseEnvFile(filepath.Join(dir, "agent.env"))
	if err != nil {
		return nil, err
	}
	getenv := envconf.EnvWithFile(vars, os.Getenv)
	return func(name string) string {
		if v := getenv(name); v != "" {
			return v
		}
		switch name {
		case "GWC_PORT":
			return serviceDefaultPort
		case "GWC_KEY_FILE":
			// Only when no key is set some other way: a _FILE twin wins
			// over its variable, so a default here would hide GWC_KEY.
			if getenv("GWC_KEY") == "" {
				return filepath.Join(dir, "agent_key")
			}
		}
		return ""
	}, nil
}

// runService hands the process to the service manager, which calls Execute.
func runService() {
	var out io.Writer = os.Stderr
	if el, err := eventlog.Open(serviceName); err == nil {
		defer el.Close()
		out = &eventWriter{log: el}
	}
	if err := svc.Run(serviceName, &agentService{out: out}); err != nil {
		fmt.Fprintf(out, "level=ERROR msg=%q\n", "service: "+err.Error())
		os.Exit(1)
	}
}

type agentService struct{ out io.Writer }

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	// A failure before the agent is listening is a service-specific exit
	// code, which the service manager counts as a failure and, with the
	// recovery actions install sets, restarts after a pause.
	fail := func(err error) (bool, uint32) {
		fmt.Fprintf(s.out, "level=ERROR msg=%q\n", err.Error())
		return true, 1
	}
	getenv, err := serviceGetenv()
	if err != nil {
		return fail(err)
	}
	cfg, err := loadConfig(os.Args[1:], getenv)
	if err != nil {
		return fail(err)
	}
	log := newLogger(s.out, cfg.logFormat, false)
	ag, err := startAgent(cfg, log)
	if err != nil {
		return true, 1
	}

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Info("shutting down", "signal", "service stop")
			status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
			stopAgent(ag, log)
			return false, 0
		}
	}
	return false, 0
}

// eventWriter sends each line the logger writes to the event log, at the
// level the line names. slog's handlers write one record per Write.
type eventWriter struct{ log *eventlog.Log }

func (w *eventWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	const eventID = 1
	var err error
	switch {
	case bytes.Contains(p, []byte("level=ERROR")), bytes.Contains(p, []byte(`"level":"ERROR"`)):
		err = w.log.Error(eventID, msg)
	case bytes.Contains(p, []byte("level=WARN")), bytes.Contains(p, []byte(`"level":"WARN"`)):
		err = w.log.Warning(eventID, msg)
	default:
		err = w.log.Info(eventID, msg)
	}
	return len(p), err
}

// serviceCommand is `gryphon-agent service install|uninstall`.
func serviceCommand(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gryphon-agent service install|uninstall")
		return 2
	}
	var err error
	switch args[0] {
	case "install":
		err = installService()
	case "uninstall":
		err = uninstallService()
	default:
		fmt.Fprintln(os.Stderr, "usage: gryphon-agent service install|uninstall")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("run this from an elevated prompt (PowerShell: Run as administrator)")
	}
	return m, err
}

func installService() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// An existing service is stopped so its program can be replaced, and
	// started again at the end if it was running.
	wasRunning := false
	s, err := m.OpenService(serviceName)
	if err == nil {
		st, qerr := s.Query()
		wasRunning = qerr == nil && st.State != svc.Stopped
		if wasRunning {
			if err := stopService(s); err != nil {
				s.Close()
				return err
			}
		}
	}

	target, err := installProgram()
	if err != nil {
		if s != nil {
			s.Close()
		}
		return err
	}

	if s == nil {
		s, err = m.CreateService(serviceName, target, mgr.Config{
			DisplayName:      serviceDisplayName,
			Description:      serviceDescription,
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
			ServiceStartName: serviceAccount,
		})
		if err != nil {
			return fmt.Errorf("creating the service: %w", err)
		}
		fmt.Println("Registered the GryphonAgent service, running as " + serviceAccount + ".")
	}
	defer s.Close()

	// Restart after a failure, as the Linux unit's Restart=on-failure does,
	// including a failure to start (a bad setting in agent.env).
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 10 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		return fmt.Errorf("setting the service's recovery actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("setting the service's recovery actions: %w", err)
	}

	// The event log source; replaced, so a moved program is found again.
	_ = eventlog.Remove(serviceName)
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("registering the event log source: %w", err)
	}

	if err := prepareDataDir(); err != nil {
		return err
	}

	if wasRunning {
		if err := s.Start(); err != nil {
			return fmt.Errorf("starting the service again: %w", err)
		}
		fmt.Println("Updated and restarted the GryphonAgent service.")
		return nil
	}
	dir := dataDir()
	fmt.Printf(`
The agent is installed and not yet running.

  1. Paste the access key into the host's Agent Access Key in Gryphon:
       Get-Content "%s"
  2. Settings, if any, go in %s
  3. Start it:
       Start-Service GryphonAgent

It starts by itself at boot from then on, and logs to the Application event log
as GryphonAgent.
`, filepath.Join(dir, "agent_key"), filepath.Join(dir, "agent.env"))
	return nil
}

// installProgram copies this program to C:\Program Files\Gryphon Agent, where
// only administrators can replace it: a service's program in a folder its
// users can write to is theirs to run as the service. It returns the path the
// service runs.
func installProgram() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	dir := programDir()
	target := filepath.Join(dir, programName)
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(target)) {
		return target, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	src, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	tmp := target + ".new"
	if err := os.WriteFile(tmp, src, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("replacing %s: %w", target, err)
	}
	fmt.Println("Installed " + target + ".")
	return target, nil
}

// prepareDataDir makes C:\ProgramData\Gryphon readable by SYSTEM,
// Administrators and the service's account and changeable by the first two
// only -- not inherited from ProgramData, which lets every user add files --
// then makes the scripts folder, the key and agent.env if they are missing.
func prepareDataDir() error {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	account, _, _, err := windows.LookupSID("", serviceAccount)
	if err != nil {
		return fmt.Errorf("looking up %s: %w", serviceAccount, err)
	}
	// FA is full access; 0x1200a9 is read and execute. OICI makes files and
	// folders inside inherit the same, and P protects the list from
	// ProgramData's.
	sddl := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + account.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("setting the permissions of %s: %w", dir, err)
	}

	// Owned by Administrators rather than by whoever ran install, which the
	// agent's script rule accepts without having to look the owner up.
	scripts := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(scripts, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		return fmt.Errorf("setting the owner of %s: %w", scripts, err)
	}

	keyPath := filepath.Join(dir, "agent_key")
	if b, err := os.ReadFile(keyPath); err != nil || len(bytes.TrimSpace(b)) == 0 {
		key, err := clientagent.GenerateKey()
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, []byte(key+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Println("Made an access key in " + keyPath + ".")
	}

	envPath := filepath.Join(dir, "agent.env")
	if _, err := os.Stat(envPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(envPath, []byte(strings.ReplaceAll(windowsAgentEnv, "\n", "\r\n")), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// stopService asks the service to stop and waits for it, up to half a minute.
func stopService(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		// Already stopping or stopped is not an error here.
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("stopping the service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return errors.New("the service did not stop within 30 seconds")
		}
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

func uninstallService() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the GryphonAgent service is not installed")
	}
	defer s.Close()
	if err := stopService(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("removing the service: %w", err)
	}
	_ = eventlog.Remove(serviceName)
	fmt.Printf(`Removed the GryphonAgent service.

Kept, for a reinstall to pick up: the key and settings in %s.
Delete that folder, and %s, to remove the agent entirely.
`, dataDir(), programDir())
	return nil
}

// windowsAgentEnv is the agent.env that install writes when there is none.
const windowsAgentEnv = `# Settings for the Gryphon Agent service. Restart the service after a change:
#   Restart-Service GryphonAgent
# The access key is not here: it is agent_key, beside this file.

# Where the agent listens. Keep it on loopback, behind a reverse proxy with TLS.
#GWC_PORT=127.0.0.1:6001

# A key being rotated out, accepted beside the new one until Gryphon has the
# new key; then remove it and restart.
#GWC_KEY_PREVIOUS=

# The Docker Engine, for the container and Swarm checks. The default is Docker's
# named pipe; the service's account must be in the docker-users group:
#   net localgroup docker-users "NT SERVICE\GryphonAgent" /add
#GWC_DOCKER_SOCKET=npipe:////./pipe/docker_engine

# Folder of scripts the script check may run (.exe, .com, .bat, .cmd or .ps1).
# The folder below was made by install with permissions the agent accepts.
#GWC_SCRIPTS_DIR=C:\ProgramData\Gryphon\scripts

# Folders the file-age check may look in, separated by semicolons. A check's
# path must be inside one of them; unset, file checks are off.
#GWC_WATCH_DIRS=D:\Backups;C:\ProgramData\MyApp\exports

# How many checks may run at once. Not a positive number means 32.
#GWC_MAX_CONCURRENT=32

# Let the network and database checks dial the public internet. Off, the agent
# reaches its own network only.
#GWC_ALLOW_PUBLIC_TARGETS=false

#GWC_LOG_FORMAT=json
`
