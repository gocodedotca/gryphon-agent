package clientagent

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// DefaultDockerSocket is where Docker Desktop and Docker Engine on Windows
// listen: a named pipe, in the spelling DOCKER_HOST uses.
const DefaultDockerSocket = "npipe:////./pipe/docker_engine"

// dockerPermissionHint is the fix for a pipe the agent may not open. Docker
// Desktop lets in Administrators and the docker-users group; the Gryphon Agent
// service's account is NT SERVICE\GryphonAgent.
const dockerPermissionHint = `the agent's account needs to be in the docker-users group: net localgroup docker-users "NT SERVICE\GryphonAgent" /add`

// dialLocal opens the Engine's named pipe, or a Unix socket, which Windows
// has too, for any other path.
func dialLocal(ctx context.Context, socket string) (net.Conn, error) {
	if path, ok := pipePath(socket); ok {
		return winio.DialPipeContext(ctx, path)
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", socket)
}
