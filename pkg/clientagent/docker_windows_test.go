package clientagent

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// Docker on Windows listens on a named pipe; the checks reach it the same way
// they reach a Unix socket.
func TestContainerCheckOverANamedPipe(t *testing.T) {
	engine := &fakeEngine{containers: map[string]map[string]any{"plain": running("running", nil)}}
	name := fmt.Sprintf(`\\.\pipe\gryphon-agent-test-%d`, time.Now().UnixNano())
	ln, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: engine}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	socket := "npipe://" + strings.ReplaceAll(name, `\`, "/")
	resp := postDocker(t, socket, "container", "container=plain")
	if resp.NewStatusID != agent.StatusHealthy || !strings.Contains(resp.Status, "running for") {
		t.Errorf("got %d %q", resp.NewStatusID, resp.Status)
	}
}

func TestDockerDefaultIsTheEnginesPipe(t *testing.T) {
	if path, ok := pipePath(DefaultDockerSocket); !ok || path != `\\.\pipe\docker_engine` {
		t.Errorf("DefaultDockerSocket %q is %q, %v", DefaultDockerSocket, path, ok)
	}
}
