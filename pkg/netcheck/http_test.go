package netcheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

func TestParseStatusSet(t *testing.T) {
	set, err := ParseStatusSet(" 200-299, 401 ,503")
	if err != nil {
		t.Fatal(err)
	}
	for code, want := range map[int]bool{200: true, 299: true, 300: false, 401: true, 404: false, 503: true} {
		if set.Accepts(code) != want {
			t.Errorf("Accepts(%d) = %v, want %v", code, !want, want)
		}
	}
	if set.String() != "200-299,401,503" {
		t.Errorf("String() = %q", set.String())
	}
	if set, _ := ParseStatusSet(""); set.String() != DefaultAcceptedStatus {
		t.Errorf("empty = %q, want the default", set.String())
	}
	for _, bad := range []string{"abc", "99", "600", "299-200", ","} {
		if _, err := ParseStatusSet(bad); err == nil {
			t.Errorf("ParseStatusSet(%q) accepted it", bad)
		}
	}
}

func TestFetchWith(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			if r.Method == http.MethodPost {
				_, _ = w.Write([]byte(`{"posted":true}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"green"}`))
		case "/auth":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	client := NewHTTPClient(5 * time.Second)
	ctx := context.Background()

	accept := func(s string) StatusSet { set, _ := ParseStatusSet(s); return set }

	for _, tc := range []struct {
		name string
		path string
		spec FetchSpec
		want int
	}{
		{"the defaults accept a 2xx", "/health", FetchSpec{}, agent.StatusHealthy},
		{"the defaults refuse a 401", "/auth", FetchSpec{}, agent.StatusProblem},
		{"a 401 can be what up looks like", "/auth", FetchSpec{Accept: accept("200,401")}, agent.StatusHealthy},
		{"text that is there is healthy", "/health", FetchSpec{Contains: `"status":"green"`}, agent.StatusHealthy},
		{"text that is not is a problem", "/health", FetchSpec{Contains: `"status":"red"`}, agent.StatusProblem},
		{"the method is the one asked for", "/health", FetchSpec{Method: http.MethodPost, Contains: `posted`}, agent.StatusHealthy},
		{"HEAD is sent", "/health", FetchSpec{Method: http.MethodHead}, agent.StatusHealthy},
		{"a method outside the list is unknown", "/health", FetchSpec{Method: http.MethodDelete}, agent.StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FetchWith(ctx, client, srv.URL+tc.path, tc.spec); got.Status != tc.want {
				t.Errorf("got %d %q, want %d", got.Status, got.Message, tc.want)
			}
		})
	}

	t.Run("a mismatch never quotes the body", func(t *testing.T) {
		got := FetchWith(ctx, client, srv.URL+"/health", FetchSpec{Contains: "red"})
		if strings.Contains(got.Message, "green") {
			t.Errorf("message %q leaks the response body", got.Message)
		}
	})

	t.Run("an address the caller's policy refuses is unknown", func(t *testing.T) {
		refusing := NewHTTPClient(5 * time.Second)
		refusing.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("127.0.0.1 is a loopback address")
		})
		spec := FetchSpec{Refused: func(err error) bool { return strings.Contains(err.Error(), "loopback") }}
		got := FetchWith(ctx, refusing, srv.URL, spec)
		if got.Status != agent.StatusUnknown || strings.Contains(got.Message, "127.0.0.1 is") {
			t.Errorf("got %d %q; want unknown, without the policy's wording", got.Status, got.Message)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseFetchSpec(t *testing.T) {
	values := map[string]string{agent.ParamMethod: "head", agent.ParamContains: "x"}
	if _, err := ParseFetchSpec(func(k string) string { return values[k] }); err == nil {
		t.Error("HEAD with text to search for was accepted")
	}
	values = map[string]string{}
	spec, err := ParseFetchSpec(func(k string) string { return values[k] })
	if err != nil || spec.Accept.String() != DefaultAcceptedStatus || spec.Method != "" {
		t.Errorf("absent settings = %+v, %v; want the defaults", spec, err)
	}
}
