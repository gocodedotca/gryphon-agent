package clientagent

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// postScript runs a script check through an agent configured with dir.
func postScript(t *testing.T, dir, name string) agent.Response {
	t.Helper()
	body, _ := json.Marshal(agent.Request{Parameters: "script=" + name})
	req := httptest.NewRequest("POST", "/script", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	Handler(Config{Key: testKey, ScriptsDir: dir}, slog.New(slog.DiscardHandler)).ServeHTTP(rec, req)
	var resp agent.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status %d: %v", rec.Code, err)
	}
	return resp
}
