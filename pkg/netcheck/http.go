package netcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

// HTTP methods a check may use. Enough for a health endpoint; a request body
// is not something a check sends.
var HTTPMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost}

// DefaultAcceptedStatus is what counts as up when a check names no codes.
const DefaultAcceptedStatus = "200-299"

// MaxContains bounds the text a response body is searched for, and
// MaxBodySearch how much of the body is searched. A health endpoint's answer
// is well inside it; a page that buries the text further down is one to point
// at something smaller.
const (
	MaxContains   = 256
	MaxBodySearch = 256 << 10
)

// FetchSpec is what a fetch asks of the response beyond answering. The zero
// value is a GET that accepts any 2xx, which is what every HTTP check did
// before it could be asked for more.
type FetchSpec struct {
	// Method is GET when empty.
	Method string
	// Accept is DefaultAcceptedStatus when nil.
	Accept StatusSet
	// Contains is text the body must include, or empty for none.
	Contains string
	// Refused, when set, reports whether a transport error is the caller's
	// own policy declining the address rather than the target failing. Such a
	// fetch is unknown: the check is pointed somewhere it may not go.
	Refused func(error) bool
	// RefusedMessage replaces the wording of such a refusal. The agent says
	// why in its own terms -- it is the operator's own network, and "this
	// installation" is the wrong machine to name.
	RefusedMessage string
}

// StatusSet is a list of accepted status codes and ranges.
type StatusSet []statusRange

type statusRange struct{ lo, hi int }

// ParseStatusSet reads "200-299", "200,401" or a mix of the two.
func ParseStatusSet(s string) (StatusSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = DefaultAcceptedStatus
	}
	var set StatusSet
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loText, hiText, isRange := strings.Cut(part, "-")
		lo, err := statusCode(loText)
		if err != nil {
			return nil, err
		}
		hi := lo
		if isRange {
			if hi, err = statusCode(hiText); err != nil {
				return nil, err
			}
			if hi < lo {
				return nil, fmt.Errorf("%s runs backwards", part)
			}
		}
		set = append(set, statusRange{lo, hi})
	}
	if len(set) == 0 {
		return nil, errors.New("no status codes given")
	}
	return set, nil
}

func statusCode(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 100 || n > 599 {
		return 0, fmt.Errorf("%q is not an HTTP status code (100 to 599)", strings.TrimSpace(s))
	}
	return n, nil
}

// Accepts reports whether code is in the set.
func (s StatusSet) Accepts(code int) bool {
	for _, r := range s {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}

// String writes the set back the way ParseStatusSet reads it.
func (s StatusSet) String() string {
	parts := make([]string, len(s))
	for i, r := range s {
		if r.lo == r.hi {
			parts[i] = strconv.Itoa(r.lo)
		} else {
			parts[i] = fmt.Sprintf("%d-%d", r.lo, r.hi)
		}
	}
	return strings.Join(parts, ",")
}

// Fetch performs a GET and maps the outcome onto a status.
func Fetch(ctx context.Context, client *http.Client, url string) Outcome {
	return FetchWith(ctx, client, url, FetchSpec{})
}

// FetchWith performs the request spec describes and maps the outcome onto a
// status.
//
// A transport failure here is a genuine problem rather than an unknown: unlike
// ICMP, being unable to complete an HTTP request to the monitored server is
// exactly the condition the check exists to detect. The exceptions are a
// resolver that is not answering, and an address the caller's policy refuses,
// neither of which tells us anything about the target.
//
// Redirects are followed, so the status judged is the final response's.
func FetchWith(ctx context.Context, client *http.Client, url string, spec FetchSpec) Outcome {
	url = strings.TrimSuffix(url, "/")

	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	if !slices.Contains(HTTPMethods, method) {
		return unknown("%s - %s is not a method this check sends", url, method)
	}
	accept := spec.Accept
	if accept == nil {
		accept, _ = ParseStatusSet(DefaultAcceptedStatus)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return unknown("%s - could not build request: %v", url, err)
	}
	req.Header.Set("User-Agent", "Gryphon")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return unknown("%s - check cancelled or timed out", url)
		}
		if spec.Refused != nil && spec.Refused(err) {
			// Without the underlying error, which can name this server's own
			// network, for the reason given on the database checks.
			if spec.RefusedMessage != "" {
				return unknown("%s - %s", url, spec.RefusedMessage)
			}
			return unknown("%s - this installation does not allow checks to reach that address", url)
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsTemporary || dnsErr.IsTimeout) {
			return unknown("%s - name server did not answer: %v", url, err)
		}
		return problem("%s - error connecting: %v", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	rtt := time.Since(start)

	if !accept.Accepts(resp.StatusCode) {
		if accept.String() != DefaultAcceptedStatus {
			return problem("%s - %s (accepted: %s)", url, resp.Status, accept)
		}
		return problem("%s - %s", url, resp.Status)
	}

	if spec.Contains != "" {
		// The body is searched and never quoted: what the check reports is
		// whether the text was there, which is all a person needs to know and
		// all a check pointed at somebody else's page should reveal.
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySearch))
		if err != nil {
			if ctx.Err() != nil {
				return unknown("%s - check cancelled or timed out", url)
			}
			return problem("%s - %s, but the response could not be read: %v", url, resp.Status, err)
		}
		if !bytes.Contains(body, []byte(spec.Contains)) {
			if len(body) == MaxBodySearch {
				return problem("%s - %s, but the first 256 KB of the response did not contain %q", url, resp.Status, spec.Contains)
			}
			return problem("%s - %s, but the response did not contain %q", url, resp.Status, spec.Contains)
		}
		rtt = time.Since(start)
	}

	return Outcome{
		Status:  agent.StatusHealthy,
		Message: fmt.Sprintf("%s - %s in %s", url, resp.Status, RoundRTT(rtt)),
		RTT:     rtt,
	}
}

// ParseFetchSpec reads the response settings out of a check's parameter
// values: agent.ParamMethod, ParamStatus and ParamContains, each absent for
// its default.
func ParseFetchSpec(get func(string) string) (FetchSpec, error) {
	spec := FetchSpec{
		Method:   strings.ToUpper(strings.TrimSpace(get(agent.ParamMethod))),
		Contains: get(agent.ParamContains),
	}
	if spec.Method != "" && !slices.Contains(HTTPMethods, spec.Method) {
		return spec, fmt.Errorf("%s is not a method this check sends", spec.Method)
	}
	accept, err := ParseStatusSet(get(agent.ParamStatus))
	if err != nil {
		return spec, err
	}
	spec.Accept = accept
	if spec.Method == http.MethodHead && spec.Contains != "" {
		return spec, errors.New("a HEAD request has no body to search")
	}
	return spec, nil
}
