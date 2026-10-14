package certificateutils

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

// Explain says why a client verifying a TLS connection would refuse it, in the
// terms of what to fix. sent is the chain the server presented, its own
// certificate first; it may be nil, at the cost of a vaguer answer about an
// unknown issuer.
//
// Shared by the certificate check and the HTTPS check, which meet the same
// refusals and used to word them differently: the HTTPS check passed Go's own
// "x509: certificate signed by unknown authority" through, which reads like a
// fault in Gryphon rather than in the site.
//
// It is ExplainFor's sentence without the subject in front, and a message
// written as subject + " - " + Explain(...) is ExplainFor's, word for word.
func Explain(err error, sent []*x509.Certificate) string {
	return strings.TrimPrefix(ExplainFor("", err, sent), " - ")
}

// ExplainFor is Explain as a check's whole message about subject -- the host
// or URL checked -- "example.com - certificate is self-signed, so nothing
// vouches for it". Each sentence is a format of its own (pkg/phrase), so the
// message is translated when it is shown; "{host} - {reason}" has too little
// fixed text to be one.
func ExplainFor(subject string, err error, sent []*x509.Certificate) string {
	var wrongName x509.HostnameError
	if errors.As(err, &wrongName) {
		names := wrongName.Certificate.DNSNames
		if len(names) == 0 && wrongName.Certificate.Subject.CommonName != "" {
			names = []string{wrongName.Certificate.Subject.CommonName}
		}
		if len(names) > 3 {
			names = append(names[:3:3], "…")
		}
		if len(names) == 0 {
			return phrase.T("{host} - certificate is not issued for {name}", "host", subject, "name", wrongName.Host)
		}
		return phrase.T("{host} - certificate is for {names}, not {name}",
			"host", subject, "names", strings.Join(names, ", "), "name", wrongName.Host)
	}

	var unknownIssuer x509.UnknownAuthorityError
	if errors.As(err, &unknownIssuer) {
		leaf := unknownIssuer.Cert
		if len(sent) > 0 {
			leaf = sent[0]
		}
		if leaf != nil {
			return unknownAuthority(subject, leaf, sent)
		}
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return phrase.T("{host} - certificate is not valid: {reason}",
			"host", subject, "reason", strings.TrimPrefix(invalid.Error(), "x509: "))
	}
	return phrase.T("{host} - certificate is not trusted: {reason}",
		"host", subject, "reason", strings.TrimPrefix(err.Error(), "x509: "))
}

// unknownAuthority tells the three ways a chain ends somewhere nothing
// trusts apart, by walking it up from the server's own certificate through
// what was sent.
//
// The common one is a server that does not send the intermediate its
// certificate was issued under — often while still sending one left over from
// a certificate it had before. A browser fetches the missing one from the
// address in the certificate, or has it cached, so the site looks fine in one;
// Go, and most clients that are not browsers, do not. That is said plainly
// only when the certificate names such an address, as every public authority's
// do: a certificate from a private authority usually has none, and then a
// missing intermediate and an issuer nobody trusts cannot be told apart.
func unknownAuthority(subject string, leaf *x509.Certificate, sent []*x509.Certificate) string {
	if SelfSigned(leaf) {
		return phrase.T("{host} - certificate is self-signed, so nothing vouches for it", "host", subject)
	}
	var rest []*x509.Certificate
	if len(sent) > 1 {
		rest = sent[1:]
	}

	used := map[*x509.Certificate]bool{}
	current := leaf
	for range len(rest) + 1 {
		if SelfSigned(current) {
			return phrase.T("{host} - certificate's chain ends at {name}, which is not a trusted authority",
				"host", subject, "name", certName(current.Subject, nil))
		}
		parent := issuerAmong(current, rest)
		if parent == nil {
			break
		}
		used[parent] = true
		current = parent
	}

	if len(current.IssuingCertificateURL) == 0 {
		return phrase.T("{host} - certificate's issuer ({issuer}) is not a trusted authority, or the server is not sending the intermediate certificate between them",
			"host", subject, "issuer", issuerName(current))
	}

	var instead []string
	for _, c := range rest {
		if !used[c] {
			instead = append(instead, certName(c.Subject, nil))
		}
	}
	// What is missing -- the intermediate that issued the server's own
	// certificate, or the one above an intermediate it did send -- and what
	// was sent in its place, if anything, are each a sentence of their own:
	// one format apiece, so that each is translated whole.
	issuer, sends := issuerName(current), strings.Join(instead, " and ")
	switch {
	case current == leaf && len(instead) == 0:
		return phrase.T("{host} - the server is not sending the intermediate certificate that issued its certificate ({issuer}). Browsers fetch a missing intermediate themselves, so the site can look fine in one, but most other clients refuse the connection. Serve the full chain: with Let's Encrypt, fullchain.pem rather than cert.pem",
			"host", subject, "issuer", issuer)
	case current == leaf:
		return phrase.T("{host} - the server is not sending the intermediate certificate that issued its certificate ({issuer}), and sends {sent} instead, which did not issue it. Browsers fetch a missing intermediate themselves, so the site can look fine in one, but most other clients refuse the connection. Serve the full chain: with Let's Encrypt, fullchain.pem rather than cert.pem",
			"host", subject, "issuer", issuer, "sent", sends)
	case len(instead) == 0:
		return phrase.T("{host} - the server is not sending the certificate that issued its intermediate {name} ({issuer}). Browsers fetch a missing intermediate themselves, so the site can look fine in one, but most other clients refuse the connection. Serve the full chain: with Let's Encrypt, fullchain.pem rather than cert.pem",
			"host", subject, "name", certName(current.Subject, nil), "issuer", issuer)
	}
	return phrase.T("{host} - the server is not sending the certificate that issued its intermediate {name} ({issuer}), and sends {sent} instead, which did not issue it. Browsers fetch a missing intermediate themselves, so the site can look fine in one, but most other clients refuse the connection. Serve the full chain: with Let's Encrypt, fullchain.pem rather than cert.pem",
		"host", subject, "name", certName(current.Subject, nil), "issuer", issuer, "sent", sends)
}

// issuerAmong finds the certificate in candidates that issued c: named as its
// issuer, and with the key that signed it.
func issuerAmong(c *x509.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	for _, candidate := range candidates {
		if candidate == c || !bytes.Equal(c.RawIssuer, candidate.RawSubject) {
			continue
		}
		if candidate.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return candidate
		}
	}
	return nil
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return "unnamed"
}
