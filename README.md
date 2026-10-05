# Gryphon Agent

The agent for Gryphon, a monitoring service. It runs on
a monitored host and measures what checks from outside cannot see: disk,
memory, CPU and load, databases and services on the host's own network, Docker
containers and Swarm services, the age of the files your jobs leave behind,
and scripts you put there. It connects out to Gryphon over HTTPS with a token
issued for its host, and answers the checks Gryphon sends down that
connection. Nothing listens on the machine.

This is the agent's source, published so that what runs on your machine can be
read. It is exported from the repository Gryphon is developed in, so pull
requests are read but not merged here; open an issue instead.

- `cmd/client` — the agent for Linux and Windows (and for a Mac that is a server)
- `cmd/client-mac` — the same agent as a macOS menu bar app, **Gryphon Agent**
- `pkg/clientagent` — the checks, and the connection to Gryphon, both of them run
- `pkg/netcheck` — the HTTP, TCP, ping and database handshakes
- `deploy/agent` — the systemd unit, its settings file, `install.sh` and a
  Docker socket proxy
- `build/macos` — how the Mac app is built, signed and notarized

## What it does and does not do

It measures the **node** it runs on: disk, memory and CPU readings are the
machine's, even inside a container. It answers the disk space, memory, CPU,
load, Postgres, MariaDB/MySQL, Redis, HTTP, HTTPS, ping, TCP, Swarm service,
Swarm stack, container, container memory and container CPU checks, scripts when
a scripts directory is set, and file freshness when watched folders are set.
It tells Gryphon that list each time it connects.

There are no thresholds in the agent. It measures and reports numbers; what
counts as a warning or a problem is decided by the server, per check.

## How it connects

The agent opens one connection to Gryphon — HTTPS on port 443, kept open as a
WebSocket — presenting its token, and keeps it open. Gryphon sends each check
down it and the agent answers on it. If the connection drops, the agent
reconnects by itself, waiting a little longer each time up to a minute; if
Gryphon refuses the token, it tries again only every five minutes. Nothing
listens on the machine, so there is no port to open, no certificate to manage
and no reverse proxy.

The token is issued by Gryphon, one per host, on the host's page, and shown
once; Gryphon keeps only its hash. Replacing it disconnects the agent using the
old one. A machine that cannot reach the internet directly can use a proxy:
`HTTPS_PROXY` in the agent's environment, as for any program; the proxy must
allow WebSocket connections.

## Build

Go (the version in `go.mod`) and, optionally, [Task](https://taskfile.dev).

```sh
task build-client                         # linux/amd64 static binary at tmp/gryphon-agent
task build-client ARCH=arm64
task build-client OS=darwin ARCH=arm64    # headless, for a Mac that is a server
task build-client OS=windows              # tmp/gryphon-agent.exe, for Windows on x64 (ARCH=arm64 for Arm)
task build-client-mac                     # "tmp/Gryphon Agent.app", ad-hoc signed: runs on this machine only
task test
```

Without Task: `CGO_ENABLED=0 go build -o gryphon-agent ./cmd/client`.

## Run

Released builds come as a `.deb`, an `.rpm` and a plain archive for Linux on
amd64 and arm64, and a `.zip` for Windows ([below](#on-windows)). The packages install the binary, a hardened systemd unit and
`/etc/gryphon/agent.env`, and leave the agent off until it has a token. Get one
from the host's page in Gryphon (**Connect an agent**), then:

```sh
sudo apt install ./gryphon-agent_<version>_amd64.deb     # or: sudo dnf install ./gryphon-agent_<version>_amd64.rpm
sudo gryphon-agent enrol                                 # paste the token; it is checked, saved and the agent started
```

`enrol` asks for the token without echoing it (or reads the first line of its
standard input, piped), checks it by connecting to Gryphon once, writes it to
`/etc/gryphon/agent_key` readable by root only, and enables and starts the
unit. `-server URL` points the agent at a Gryphon other than the default and
records it in `agent.env`; `-no-start` saves the token without starting.

`deploy/agent/install.sh` does the same as the packages from the release
archive, after checking it against the release's `SHA256SUMS`. Read it before
running it as root.

By hand, with the token in a file only you can read:

```sh
read -rsp "Token: " TOKEN; echo
(umask 077; printf '%s\n' "$TOKEN" > agent_key); unset TOKEN
GWC_KEY_FILE=./agent_key ./gryphon-agent
```

Settings are defaults, then `GWC_*` environment variables, then flags. Every
variable also has a `_FILE` twin naming a file to read the value from
(`GWC_KEY_FILE=/run/secrets/gryphon_agent_key`), for secrets mounted by an
orchestrator. `GWC_KEY_FILE=-` reads the token from standard input, once, at
startup; the systemd unit uses it so that the agent's own user never has a path
to the token file (see [The systemd unit](#the-systemd-unit)).

| Environment variable | Flag           | Default   | Purpose |
|----------------------|----------------|-----------|---------|
| `GWC_KEY`            | *(none)*       | *(none)*  | The token from the host's page in Gryphon. Required |
| `GWC_SERVER`         | `-server`      | `https://gryphon.gocode.ca` | The Gryphon to connect to |
| `GWC_ALLOW_INSECURE_SERVER` | `-allow-insecure-server` | `false` | Allow an `http://` server: for development, or an installation reached only across its own network |
| `GWC_LOG_FORMAT`     | `-logformat`   | `text`    | `text` or `json` |
| `GWC_DOCKER_SOCKET`  | `-docker-socket` | `/var/run/docker.sock` | The Docker Engine, for the container and Swarm checks: a socket path, or `tcp://host:port` for a socket proxy |
| `GWC_MAX_CONCURRENT` | `-max-concurrent` | `32`     | How many checks may run at once; past it a check answers unknown, "the agent is busy" |
| `GWC_WATCH_DIRS`     | `-watch-dirs`  | *(none)*  | Folders the file freshness checks may look in, separated as `PATH` is (`:` on Unix, `;` on Windows). Unset, file checks are off |
| `GWC_SCRIPTS_DIR`    | `-scripts-dir` | *(none)*  | Directory of executables the script checks run by name. Unset, script checks are off |
| `GWC_ALLOW_PUBLIC_TARGETS` | `-allow-public-targets` | `false` | Let the network and database checks dial the public internet (below) |
|                      | `-version`     |           | Print the build and exit |

The token has no flag on purpose: a command line is visible to every user on
the machine through `ps`. To change it, replace the token on the host's page and
run `enrol` again with the new one.

## Where checks may connect

The HTTP, HTTPS, ping, TCP and database checks take an address from Gryphon and
run from inside your network, so by default they may reach **only** that
network: loopback, RFC 1918, IPv6 unique local, shared address space, and any
name that resolves to one of those. A public address is refused, and the check
reports unknown with the reason. Link-local is refused too, because that is
where every cloud's metadata endpoint lives.

The agent makes that decision when it dials, on the address it actually
arrives at, not on the name. `GWC_ALLOW_PUBLIC_TARGETS` (`allow_public_targets`
in the Mac app's settings) lifts the refusal entirely.

## Script checks

A script check runs an executable from `GWC_SCRIPTS_DIR` by its file name, with
no arguments, and reads the exit code as a Nagios plugin reports it: `0`
healthy, `1` warning, `2` problem, `3` unknown; anything else, or no exit
within 10 seconds, is unknown. The first line of output is the message, cut at
a `|` so performance data stays out of it.

Gryphon sends only the name, so what may run is decided on the host, by what is
in that directory. The name must be a bare file name (letters, digits, `.`,
`-`, `_`; not starting with `.` or `-`; at most 64 characters), and the agent
refuses anything but a regular executable file, a script every user can write
to, a script owned by anyone but root or the agent's own user, and a
group-writable script whose group the agent is not in. The directory is held to
the same rules. Scripts run as the agent's user, with the agent's environment
less its own `GWC_*` settings, at most four at a time.

A script cannot read the agent's token on Linux. The agent marks itself not
dumpable as it starts, so a process of the same user -- a script, or anything a
script runs -- cannot read its memory, environment or open files through
`/proc` or ptrace, and under the systemd unit the token file is root's. On
**Windows** that is not so: a script runs as the service's account, which can
read `agent_key` and `agent.env`, so put only scripts you trust in the scripts
folder. On macOS the agent is your own app, running your own scripts as you. A plugin that needs
arguments is a two-line wrapper:

```sh
#!/bin/sh
exec /usr/lib/nagios/plugins/check_procs -c 1: -C nginx
```

## File checks

A file freshness check asks how long ago a file was written, or, for a folder,
the newest regular file directly in it (not its subfolders), optionally only
names matching a pattern such as `*.sql.gz`. The agent reports the age in hours
and the server grades it; a missing file, a folder with no matching file, or a
file under the check's minimum size is reported as a problem by the agent
itself.

Gryphon sends an absolute path, and the agent answers only for paths inside a
folder in `GWC_WATCH_DIRS`. Anything else is refused before the file system is
asked, so neither a Gryphon login nor the token can learn what exists elsewhere.
Links are followed only while they stay inside those folders, links inside a
folder are passed over, and a folder of more than 100,000 entries is refused.
The agent lists folders and reads dates and sizes; it never opens a file.

## Ping and Docker

Ping uses ICMP where the agent may send it, and a TCP probe of 443, 80 and 22
where it may not. On Linux an unprivileged agent can send ICMP when its group
is inside `net.ipv4.ping_group_range`, or with `CAP_NET_RAW`.

The container and Swarm checks ask the Docker Engine a fixed set of read-only
questions about the container or service a check names; no path or query comes
from Gryphon. Access to the Engine's socket is root-equivalent, so the
recommended way is `deploy/agent/docker-socket-proxy.yml`, a proxy that lets
through only reads of containers, services and tasks, with
`GWC_DOCKER_SOCKET=tcp://127.0.0.1:2375`. The Swarm checks need a manager
node's Engine.

## The systemd unit

`deploy/agent/gryphon-agent.service` runs the agent as a throwaway user with no
capabilities, a read-only system and no new privileges, and reads
`/etc/gryphon/agent.env`. The token in `/etc/gryphon/agent_key` stays readable by
root only: systemd opens it and passes it to the agent on standard input, which
the agent reads once and closes, and the unit does not start until it exists.
`agent.env` is root's only too, since it can hold a proxy's credentials and
only systemd reads it. Updates replace the unit, so change it with a drop-in
(`sudo systemctl edit gryphon-agent`):

```ini
[Service]
# ICMP for the ping check
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
# Direct access to the Docker socket (root-equivalent; prefer the proxy)
SupplementaryGroups=docker
# A group that may list a watched folder, for the file freshness checks
#SupplementaryGroups=backup
```

## On macOS

**Gryphon Agent** is the same agent as a menu bar app: no Dock icon, no window,
a menu to turn it on and off, enter its token, open it at login and edit its
settings, and a first line saying whether it is connected. On first launch it
has no token; choose **Enter Token…** and paste the one from the host's page in
Gryphon.

Settings live in `~/Library/Application Support/Gryphon Agent/config.json`,
readable by its owner only:

```json
{
  "token": "<token>",
  "enabled": true,
  "scripts_dir": "/Users/you/Library/Application Support/Gryphon Agent/scripts",
  "watch_dirs": ["/Users/you/Backups"],
  "allow_public_targets": false
}
```

`"server"` (and `"allow_insecure_server"` for `http://`) point it at a Gryphon
other than the default; the first line of the menu names the server whenever
it is not the default.

It logs to `~/Library/Logs/Gryphon Agent.log`. Once a day it asks GitHub for
the latest release and offers a link when there is a newer one; it never
downloads or installs anything itself.

## On Windows

The same agent runs on Windows 10 and 11 and Windows Server 2016 or later, on
x64 or Arm, as a Windows service. Every check works there, with the
differences listed below.

### Install

Download `gryphon-agent_<version>_windows_amd64.zip` (or `_arm64`) and
`SHA256SUMS` from the release, and check the one against the other in
PowerShell:

```powershell
(Get-FileHash .\gryphon-agent_<version>_windows_amd64.zip).Hash.ToLower()
Select-String "windows_amd64.zip" .\SHA256SUMS      # the two must match
Expand-Archive .\gryphon-agent_<version>_windows_amd64.zip -DestinationPath .\gryphon-agent
```

Then, from PowerShell opened with **Run as administrator**:

```powershell
.\gryphon-agent\gryphon-agent.exe service install
& 'C:\Program Files\Gryphon Agent\gryphon-agent.exe' enrol   # paste the token; it is checked, saved and the service started
```

`service install`:

- copies the program to `C:\Program Files\Gryphon Agent\`, where only
  administrators can replace it. The downloaded copy can be deleted afterwards.
- makes `C:\ProgramData\Gryphon\` for the agent's token, settings and scripts.
  Only SYSTEM and Administrators can change anything in it, and only the service
  can read it.
- writes a commented `agent.env`.
- registers the **GryphonAgent** service. It starts automatically at boot and
  restarts after a failure, but install does not start it: it has no token
  until `enrol` gives it one, which starts it.

The service runs as the virtual account `NT SERVICE\GryphonAgent`, with no
password and no rights beyond an ordinary user's. It connects out to Gryphon
and listens on nothing, and logs to the Application event log as source
`GryphonAgent` (Event Viewer → Windows Logs → Application):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='GryphonAgent'} -MaxEvents 20
```

### Settings

Settings go in `C:\ProgramData\Gryphon\agent.env`: the same `GWC_*` variables
as on Linux, one per line. Restart the service after changing it:

```powershell
notepad C:\ProgramData\Gryphon\agent.env
Restart-Service GryphonAgent
```

The token stays in `agent_key`. To change it, replace it on the host's page in
Gryphon and run `enrol` again with the new one.

### The network

As on Linux, the agent connects out to Gryphon on port 443 and nothing
connects to it, so Windows Firewall needs no rule. Behind a proxy, set
`HTTPS_PROXY` in `agent.env`.

### What differs from Linux

- **Disk space** takes a drive or folder as its path: `C:\`, `D:\`, or
  `C:\ClusterStorage\Volume1`. The default, `/`, is the root of the drive the
  agent runs from, which for the service is the system drive. Windows has no
  inodes, so only space is judged.
- **Load** doesn't exist as such on Windows. The agent reports an estimate
  built from the processor queue length, sampled every five seconds from the
  first time a load check asks. That first answer is 0, and the figure settles
  within a minute or two. CPU is
  the better check on Windows.
- **Ping**: sending ICMP needs an administrator on Windows, so under the
  service the check normally uses its fallback, a TCP probe of ports 443, 80
  and 22, as on Linux. A host that answers on none of them reports unknown,
  not down.
- **Docker** is reached through Docker's named pipe,
  `npipe:////./pipe/docker_engine`, which is the default. Docker Desktop lets
  Administrators and the `docker-users` group open it, so add the service's
  account and restart:

  ```powershell
  net localgroup docker-users "NT SERVICE\GryphonAgent" /add
  Restart-Service GryphonAgent
  ```

  As on Linux, that access is equivalent to administrator rights on the
  machine. Docker Desktop's **Expose daemon on tcp://localhost:2375** setting
  with `GWC_DOCKER_SOCKET=tcp://127.0.0.1:2375` is the alternative. It doesn't
  need the group, but every local user can reach that port.
- **Scripts** run from `C:\ProgramData\Gryphon\scripts` once `agent.env` has
  `GWC_SCRIPTS_DIR=C:\ProgramData\Gryphon\scripts`. Gryphon sends the full file
  name, extension included (`disk_queue.ps1`), and the agent runs `.exe`,
  `.com`, `.bat`, `.cmd` and `.ps1` files. A `.ps1` runs in Windows
  PowerShell, bypassing the execution policy for that file only. Exit codes
  are read as on Linux (`exit 2` in PowerShell, `exit /b 2` in a batch file).
  Scripts time out after 10 seconds, and the agent then ends everything the
  script started.
- **File checks** look in the folders `GWC_WATCH_DIRS` names, separated by
  semicolons (`D:\Backups;C:\ProgramData\MyApp\exports`). The service's
  account must be able to list them.

  The rules are the Linux ones in Windows terms. The folder and each script
  must be owned by SYSTEM, Administrators, an administrator or the agent's
  account, and nobody else may be allowed to change, add, delete or
  re-permission them. A file created in the scripts folder picks up permissions
  that pass. A file **moved** in from elsewhere keeps its old permissions, and
  the agent refuses it with a message naming the account that can change it
  and the `icacls` command that fixes it. A folder you make yourself under
  `C:\ProgramData` fails until its permissions are narrowed, because
  ProgramData lets every user create files in new folders.

### Updating and removing

To update, download the newer zip and run its `service install` from an
elevated PowerShell. It stops the service, replaces the program, and starts it
again, keeping the token and `agent.env`.

```powershell
& "C:\Program Files\Gryphon Agent\gryphon-agent.exe" service uninstall
```

removes the service and its event log source. It keeps
`C:\ProgramData\Gryphon` (token and settings) and `C:\Program Files\Gryphon Agent`.
Delete both to remove everything.

### Without the service

The program also runs in a console, configured like on Linux, for trying it
out:

```powershell
$env:GWC_KEY = Read-Host "Token"
.\gryphon-agent.exe
```

Stop it with Ctrl+C.

## Licence

MIT; see `LICENSE`.
