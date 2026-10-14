// Package certificateutils is based on https://github.com/asyncsrc/ssl_scan
package certificateutils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

var (
	errHostNameEmpty = errors.New(phrase.Mark("hostname empty"))
)

// ResultError holds the result of certificate errors
type ResultError struct {
	Res CertificateDetails
	Err error
}

// CertificateDetails holds info about a certificate
type CertificateDetails struct {
	DaysUntilExpiration int
	IssuerName          string
	SubjectName         string
	SerialNumber        string
	ExpiringSoon        bool
	Expired             bool
	Hostname            string
	TimeTaken           time.Duration
	ExpirationDate      string
	Thumbprint          string

	// NotAfter is when the server's own certificate expires.
	NotAfter time.Time
	// VerifyError is why a client verifying the connection would refuse it
	// -- an issuer no trusted root vouches for, a missing intermediate, a
	// name the certificate was not issued for -- or nil when it would
	// accept it. It is always worked out; whether it matters is the caller's
	// decision. Set only by the functions that dial.
	VerifyError error
	// ChainExpiry is the earliest expiry among the intermediates the server
	// sent, and ChainExpiryName the certificate it belongs to, when that is
	// sooner than the server's own. A site whose certificate has a year left
	// still breaks the day the intermediate it was issued under lapses. Zero
	// when no intermediate expires first.
	ChainExpiry     time.Time
	ChainExpiryName string
	// Chain is what the server sent, its own certificate first, for
	// Explain to say which link of it is missing. Set only by the functions
	// that dial.
	Chain []*x509.Certificate
}

// String returns a formatted string response
func (cd CertificateDetails) String() string {
	return fmt.Sprintf(
		"Subject Name: %s\nIssuer: %s\nExpiration date: %s\nDays Until Expiration: %d\nSerial #: %s\nRequest Time: %v\n",
		cd.SubjectName,
		cd.IssuerName,
		cd.ExpirationDate,
		cd.DaysUntilExpiration,
		cd.SerialNumber,
		cd.TimeTaken,
	)
}

// insertNth
func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	var n1 = n - 1
	var l1 = len(s) - 1
	for i, r := range s {
		buffer.WriteRune(r)
		if i%n == n1 && i != l1 {
			buffer.WriteRune('-')

		}
	}
	return buffer.String()
}

// ReadCertificateDetailsFromFile reads a cert from disk
func ReadCertificateDetailsFromFile(publicCertFile, privateCertFile string) ([]CertificateDetails, error) {
	currentTime := time.Now()
	var certDetails []CertificateDetails
	var blocks []byte

	rest, err := os.ReadFile(publicCertFile)
	if err != nil {
		return certDetails, err
	}

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)

		if block == nil {
			return certDetails, errors.New("certificate doesn't have a valid PEM block")
		}

		blocks = append(blocks, block.Bytes...)
		if len(rest) == 0 {
			break
		}
	}

	certs, err := x509.ParseCertificates(blocks)
	if err != nil {
		return certDetails, err
	}

	for _, cert := range certs {
		daysUntilExpiration := int(cert.NotAfter.Sub(currentTime).Hours() / 24)
		serialNumber := cert.SerialNumber.Text(16)
		elapsed := time.Since(currentTime)

		certDetails = append(certDetails, CertificateDetails{
			DaysUntilExpiration: daysUntilExpiration,
			SubjectName:         certName(cert.Subject, cert.DNSNames),
			IssuerName:          certName(cert.Issuer, nil),
			SerialNumber:        strings.ToUpper(insertNth(serialNumber, 2)),
			TimeTaken:           elapsed,
			ExpirationDate:      cert.NotAfter.Format(time.UnixDate),
		})

	}

	return certDetails, nil
}

// GetCertificateDetails gets a certificate and its details
func GetCertificateDetails(hostname string, connectionTimeout int) (CertificateDetails, error) {
	return GetCertificateDetailsWith(&net.Dialer{Timeout: time.Second * time.Duration(connectionTimeout)}, hostname)
}

// GetCertificateDetailsWith is GetCertificateDetails through dialer, which is
// how a caller holds the connection to an outbound policy. A connection error
// is wrapped, so the caller can tell the policy's refusal from the target's.
// The certificate is verified against the system's roots; see InspectWith.
func GetCertificateDetailsWith(dialer *net.Dialer, hostname string) (CertificateDetails, error) {
	return InspectWith(dialer, hostname, nil)
}

// InspectWith reads the certificate hostname presents and verifies it.
//
// The certificate is read without verification first, deliberately: a
// certificate that has expired, or that nothing trusts, still has a date on
// it, and the date is half of what the check reports. Verification is then
// done by hand against roots -- the system's own when nil -- with the
// intermediates the server sent and the name that was dialled, which is what
// a browser does, and its answer is VerifyError.
func InspectWith(dialer *net.Dialer, hostname string, roots *x509.CertPool) (CertificateDetails, error) {
	currentTime := time.Now()
	var certDetails CertificateDetails

	if hostname == "" {
		return CertificateDetails{}, errHostNameEmpty
	}

	if !strings.Contains(hostname, ":") {
		hostname = fmt.Sprintf("%s:443", hostname)
	}

	// Establish a new TCP connection to hostname
	// Ignore invalid certificates, so we can scan via IP addresses or hostnames
	conn, err := tls.DialWithDialer(dialer,
		"tcp",
		hostname,
		&tls.Config{InsecureSkipVerify: true})

	if err != nil {
		return CertificateDetails{}, phrase.Errorf("connection error: {err}", "err", err)
	}

	if handshakeCompleted := conn.ConnectionState().HandshakeComplete; !handshakeCompleted {
		return CertificateDetails{}, phrase.Errorf("the TLS Handshake failed to hostname {host}", "host", hostname)
	}

	defer conn.Close()

	// The server's own certificate is always the first one it sends (RFC 8446
	// section 4.4.2; RFC 5246 section 7.4.2 before it). This used to take the
	// first certificate not marked as a CA instead, which found nothing for a
	// self-signed certificate that is its own CA -- and reported it as expiring
	// in 0 days.
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return CertificateDetails{}, phrase.Errorf("{host} presented no certificate", "host", hostname)
	}
	cert := peers[0]

	certDetails = CertificateDetails{
		DaysUntilExpiration: int(cert.NotAfter.Sub(currentTime).Hours() / 24),
		SubjectName:         certName(cert.Subject, cert.DNSNames),
		IssuerName:          certName(cert.Issuer, nil),
		SerialNumber:        strings.ToUpper(insertNth(cert.SerialNumber.Text(16), 2)),
		Hostname:            hostname,
		TimeTaken:           time.Since(currentTime),
		ExpirationDate:      cert.NotAfter.Format(time.UnixDate),
		NotAfter:            cert.NotAfter,
		Chain:               peers,
	}

	// The name the certificate has to be for is the one dialled, less the
	// port. An address works too: VerifyHostname matches it against the
	// certificate's IP addresses.
	name := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		name = h
	}
	intermediates := x509.NewCertPool()
	for _, c := range peers[1:] {
		intermediates.AddCert(c)
	}
	_, certDetails.VerifyError = cert.Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
	})

	// The intermediates' own lifetimes. A root the server sends along is
	// left out: a client uses the copy in its own store, not this one, and
	// many servers send an old cross-signed root that has long expired
	// without anything being wrong.
	for _, c := range peers[1:] {
		if SelfSigned(c) || !c.NotAfter.Before(cert.NotAfter) {
			continue
		}
		if certDetails.ChainExpiry.IsZero() || c.NotAfter.Before(certDetails.ChainExpiry) {
			certDetails.ChainExpiry = c.NotAfter
			certDetails.ChainExpiryName = certName(c.Subject, nil)
		}
	}

	return certDetails, nil
}

// SelfSigned reports whether a certificate is issued by itself and signed
// with its own key: a root, or a server certificate nobody else vouches for.
// The signature is checked directly rather than with CheckSignatureFrom,
// which refuses a certificate that is not marked as a CA as its own parent --
// and a self-signed server certificate usually is not.
func SelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// certName is how a certificate names its subject or issuer: the common name,
// then the organisation, then the first DNS name, for a certificate that names
// itself only there, as many now do. It used to read the last attribute of the
// name with an unchecked index and type assertion, which panicked on an empty
// subject -- in a goroutine nothing recovers, so one certificate could stop
// the server.
func certName(name pkix.Name, dnsNames []string) string {
	if name.CommonName != "" {
		return name.CommonName
	}
	if len(name.Organization) > 0 {
		return name.Organization[0]
	}
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	return ""
}

// CheckExpirationStatus checks the expiration info for a certificate
func CheckExpirationStatus(cd *CertificateDetails, expirationDaysThreshold int) {
	if cd.DaysUntilExpiration < 0 {
		cd.Expired = true
	} else if cd.DaysUntilExpiration < expirationDaysThreshold {
		cd.ExpiringSoon = true
	}
}
