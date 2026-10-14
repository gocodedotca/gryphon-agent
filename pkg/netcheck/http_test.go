package netcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
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

// A server sending its certificate with someone else's intermediate — stu.ca's
// shape: a Let's Encrypt certificate, and a GeoTrust intermediate left over
// from the certificate before it. Browsers fetch the missing intermediate; Go
// refuses, and the check has to say why in words that point at the site.
func TestFetchSaysWhichIntermediateIsMissing(t *testing.T) {
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	serial := int64(1)
	issue := func(tmpl *x509.Certificate, parent *x509.Certificate, parentKey, k *ecdsa.PrivateKey) *x509.Certificate {
		serial++
		tmpl.SerialNumber = big.NewInt(serial)
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		if parent == nil {
			parent, parentKey = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ca := func(name string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	}

	rootKey, interKey, oldKey, leafKey := key(), key(), key(), key()
	root := issue(ca("ISRG Root"), nil, nil, rootKey)
	inter := issue(ca("YE1"), root, rootKey, interKey)
	stale := issue(ca("GeoTrust TLS RSA CA G1"), nil, nil, oldKey)
	leaf := issue(&x509.Certificate{
		Subject: pkix.Name{CommonName: "stu.ca"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IssuingCertificateURL: []string{"http://ye1.i.lencr.org/"},
		KeyUsage:              x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, inter, interKey, leafKey)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, stale.Raw}, PrivateKey: leafKey}}}
	// The refusal is the point; the server's log of it is noise.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(root)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}

	got := Fetch(context.Background(), client, srv.URL)
	if got.Status != agent.StatusProblem {
		t.Fatalf("status %v, want a problem: %q", got.Status, got.Message)
	}
	for _, want := range []string{
		"not sending the intermediate certificate that issued its certificate (YE1)",
		"sends GeoTrust TLS RSA CA G1 instead",
		"fullchain.pem",
	} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message %q does not say %q", got.Message, want)
		}
	}
	if strings.Contains(got.Message, "x509:") {
		t.Errorf("message %q still passes Go's own error through", got.Message)
	}
}
