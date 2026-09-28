//go:build !windows

package clientagent

import (
	"context"
	"net"
)

// DefaultDockerSocket is where the Docker Engine listens unless told otherwise.
const DefaultDockerSocket = "/var/run/docker.sock"

// dockerPermissionHint is the fix for a socket the agent may not open.
const dockerPermissionHint = "the agent's user needs to be in the docker group"

// dialLocal opens the Engine's Unix socket.
func dialLocal(ctx context.Context, socket string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socket)
}
