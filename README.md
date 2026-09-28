# Gryphon Agent

The agent for Gryphon, a monitoring service. It runs on
a monitored host and measures what checks from outside cannot see: disk,
memory, CPU and load, databases and services on the host's own network, Docker
containers and Swarm services, and scripts you put there. Gryphon posts to it
with the host's access key and it answers with a status.

This is the agent's source, published so that what runs on your machine can be
read. It is exported from the repository Gryphon is developed in, so pull
requests are read but not merged here; open an issue instead.

- `cmd/client` — the agent for Linux (and for a Mac that is a server)
- `cmd/client-mac` — the same agent as a macOS menu bar app, **Gryphon Agent**
- `pkg/clientagent` — the checks and the HTTP service both of them run
- `pkg/netcheck` — the HTTP, TCP, ping and database handshakes
- `deploy/agent` — the systemd unit, its settings file, `install.sh`, a
  Caddyfile and a Docker socket proxy
- `build/macos` — how the Mac app is built, signed and notarized

## What it does and does not do

It measures the **node** it runs on: disk, memory and CPU readings are the
machine's, even inside a container. It answers the disk space, memory, CPU,
load, Postgres, MariaDB/MySQL, Redis, HTTP, HTTPS, ping, TCP, Swarm service,
Swarm stack, container, container memory and container CPU checks, and scripts
when a scripts directory is set. `GET /test` returns that list.

There are no thresholds in the agent. It measures and reports numbers; what
counts as a warning or a problem is decided by the server, per check.

Every request needs the access key, as `Authorization: Bearer <key>`, compared
in constant time; there is no way to run without one. Past 60 wrong keys a
minute from one address, that address gets 429 until the minute passes.
`GET /healthz` answers `ok` without a key, for a watchdog or load balancer.

## Build

Go (the version in `go.mod`) and, optionally, [Task](https://taskfile.dev).

```sh
task build-client                         # linux/amd64 static binary at tmp/gowatcher-client
task build-client ARCH=arm64
task build-client OS=darwin ARCH=arm64    # headless, for a Mac that is a server
task build-client-mac                     # "tmp/Gryphon Agent.app", ad-hoc signed: runs on this machine only
task test
```

Without Task: `CGO_ENABLED=0 go build -o gowatcher-client ./cmd/client`.

## Run

Released builds come as a `.deb`, an `.rpm` and a plain archive for Linux on
amd64 and arm64. The packages install the binary, a hardened systemd unit and
`/etc/gryphon/agent.env`, make an access key in `/etc/gryphon/agent_key`, and
leave the agent off:

```sh
sudo apt install ./gryphon-agent_<version>_amd64.deb     # or: sudo dnf install ./gryphon-agent_<version>_amd64.rpm
sudo cat /etc/gryphon/agent_key                          # paste into the host in Gryphon
sudo systemctl enable --now gryphon-agent
```

`deploy/agent/install.sh` does the same from the release archive, after
checking it against the release's `SHA256SUMS`. Read it before running it as
root.

By hand:

```sh
./gowatcher-client -genkey                  # prints a new key; keep it
GWC_KEY=<that key> ./gowatcher-client -port 127.0.0.1:6001
```

Settings are defaults, then `GWC_*` environment variables, then flags. Every
variable also has a `_FILE` twin naming a file to read the value from
(`GWC_KEY_FILE=/run/secrets/gryphon_agent_key`), for secrets mounted by an
orchestrator.

| Environment variable | Flag           | Default   | Purpose |
|----------------------|----------------|-----------|---------|
| `GWC_KEY`            | *(none)*       | *(none)*  | The access key, 32 to 256 printable ASCII characters. Required |
| `GWC_KEY_PREVIOUS`   | *(none)*       | *(none)*  | A second key accepted while the key is rotated |
| `GWC_PORT`           | `-port`        | `:6001`   | Address to listen on. The packaged unit sets `127.0.0.1:6001` |
| `GWC_LOG_FORMAT`     | `-logformat`   | `text`    | `text` or `json` |
| `GWC_DOCKER_SOCKET`  | `-docker-socket` | `/var/run/docker.sock` | The Docker Engine, for the container and Swarm checks: a socket path, or `tcp://host:port` for a socket proxy |
| `GWC_MAX_CONCURRENT` | `-max-concurrent` | `32`     | How many checks may run at once; past it a check answers unknown, "the agent is busy" |
| `GWC_SCRIPTS_DIR`    | `-scripts-dir` | *(none)*  | Directory of executables the script checks run by name. Unset, script checks are off |
| `GWC_ALLOW_PUBLIC_TARGETS` | `-allow-public-targets` | `false` | Let the network and database checks dial the public internet (below) |
|                      | `-genkey`      |           | Print a new access key and exit |
|                      | `-version`     |           | Print the build and exit |

The key has no flag on purpose: a command line is visible to every user on the
machine through `ps`. To change it without a gap, put the new key in `GWC_KEY`
and the old one in `GWC_KEY_PREVIOUS` until Gryphon has the new one.

## Put it behind TLS

The key travels in a header, so over plain `http://` anyone on the path can
read it, along with any database connection string a check sends. Bind the
agent to loopback, terminate TLS in a reverse proxy and give Gryphon the
`https://` URL. With Caddy (`deploy/agent/Caddyfile`):

```
agent.example.com {
	reverse_proxy 127.0.0.1:6001
}
```

On a Mac, a tunnel does the same without opening a port: Cloudflare Tunnel
(`cloudflared tunnel --url http://127.0.0.1:6001`) or Tailscale Funnel
(`tailscale funnel 6001`).

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
less its own `GWC_*` settings, at most four at a time. A plugin that needs
arguments is a two-line wrapper:

```sh
#!/bin/sh
exec /usr/lib/nagios/plugins/check_procs -c 1: -C nginx
```

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
capabilities, a read-only system and no new privileges, hands it the key from
`/etc/gryphon/agent_key` through systemd credentials, and reads
`/etc/gryphon/agent.env`. Updates replace the unit, so change it with a drop-in
(`sudo systemctl edit gryphon-agent`):

```ini
[Service]
# ICMP for the ping check
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
# Direct access to the Docker socket (root-equivalent; prefer the proxy)
SupplementaryGroups=docker
```

## On macOS

**Gryphon Agent** is the same agent as a menu bar app: no Dock icon, no window,
a menu to turn it on and off, open it at login, copy the access key and edit
its settings. On first launch it listens on port 6001 on every interface and
makes a new key; set the port to loopback before exposing it through anything.

Settings live in `~/Library/Application Support/Gryphon Agent/config.json`,
readable by its owner only:

```json
{
  "port": "127.0.0.1:6001",
  "access_key": "<key>",
  "enabled": true,
  "scripts_dir": "/Users/you/Library/Application Support/Gryphon Agent/scripts",
  "allow_public_targets": false
}
```

It logs to `~/Library/Logs/Gryphon Agent.log`. Once a day it asks GitHub for
the latest release and offers a link when there is a newer one; it never
downloads or installs anything itself.

## Licence

MIT; see `LICENSE`.
