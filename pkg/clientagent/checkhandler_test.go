package clientagent

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// checkHandler puts an HTTP face on run, for the tests that exercise checks
// through a request and a JSON answer: POST /<check> with {"parameters": ...},
// and GET or POST /test. The agent itself has no HTTP side any more -- it
// takes its requests over the connection to Gryphon -- but a check answers
// the same whichever way it was asked, and this keeps those tests reading as
// requests.
func checkHandler(cfg Config, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := newHandlers(cfg.withDefaults(), log)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := strings.TrimPrefix(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		if action == "test" {
			_ = json.NewEncoder(w).Encode(h.testResponse())
			return
		}
		var req struct {
			Parameters string `json:"parameters"`
		}
		if b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)); len(b) > 0 {
			_ = json.Unmarshal(b, &req)
		}
		code, resp := h.run(r.Context(), action, req.Parameters)
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	})
}
