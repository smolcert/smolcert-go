package smolcert

import (
	"crypto/rand"
	"time"

	"golang.org/x/crypto/ed25519"
)

func ensureExtension(extensions []Extension, extp Extension) []Extension {
	found := false
	for _, ext := range extensions {
		if ext.OID == extp.OID {
			ext.Critical = extp.Critical
			ext.Value = extp.Value
			found = true
			break
		}
	}
	if !found {
		extensions = append(extensions, extp)
	}
	return extensions
}

// SignCertificate takes a certificate, removes the signature and creates a new signature with the given key
func SignCertificate(cert *Certificate, priv ed25519.PrivateKey) (*Certificate, error) {
	cert.Signature = nil
	certBytes, err := cert.Bytes()
	if err != nil {
		return nil, err
	}
	cert.Signature = ed25519.Sign(priv, certBytes)
	return cert, nil
}

// ClientCertificate is a convenience function to create a valid client certificate
func ClientCertificate(subject string, serialNumber uint64, notBefore, notAfter time.Time,
	extensions []Extension, rootKey ed25519.PrivateKey, issuer string) (*Certificate, ed25519.PrivateKey, error) {
	extensions = ensureExtension(extensions, Extension{
		OID:      OIDKeyUsage,
		Critical: true,
		Value:    KeyUsageClientIdentification.ToBytes(),
	})
	return SignedCertificate(subject, serialNumber, notBefore, notAfter, extensions, rootKey, issuer)
}

// ServerCertificate is a convenience function to create a valid server certificate
func ServerCertificate(subject string, serialNumber uint64, notBefore, notAfter time.Time,
	extensions []Extension, rootKey ed25519.PrivateKey, issuer string) (*Certificate, ed25519.PrivateKey, error) {
	extensions = ensureExtension(extensions, Extension{
		OID:      OIDKeyUsage,
		Critical: true,
		Value:    KeyUsageServerIdentification.ToBytes(),
	})
	return SignedCertificate(subject, serialNumber, notBefore, notAfter, extensions, rootKey, issuer)
}

// SignedCertificate creates a new certificate signed with the specified rooKey and issuer.
func SignedCertificate(subject string, serialNumber uint64, notBefore, notAfter time.Time,
	extensions []Extension, rootKey ed25519.PrivateKey, issuer string) (*Certificate, ed25519.PrivateKey, error) {

	validity := &Validity{}
	if extensions == nil {
		extensions = []Extension{}
	}

	if notBefore.IsZero() {
		validity.NotBefore = ZeroTime
	} else {
		validity.NotBefore = NewTime(notBefore)
	}
	if notAfter.IsZero() {
		validity.NotAfter = ZeroTime
	} else {
		validity.NotAfter = NewTime(notAfter)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ed25519.PrivateKey{}, err
	}
	cert := &Certificate{
		Version:      smolcertVersion,
		SerialNumber: serialNumber,
		Issuer:       issuer,
		Validity:     validity,
		Subject:      subject,
		PubKey:       pub,
		Extensions:   extensions,
		Signature:    nil,
	}
	cert, err = SignCertificate(cert, rootKey)
	return cert, priv, err
}

// SelfSignedCertificate is a simple function to generate a self signed certificate
func SelfSignedCertificate(subject string,
	notBefore, notAfter time.Time,
	extensions []Extension) (*Certificate, ed25519.PrivateKey, error) {
	validity := &Validity{}
	if extensions == nil {
		extensions = []Extension{}
	}
	extensions = ensureExtension(extensions, Extension{
		OID:      OIDKeyUsage,
		Critical: true,
		Value:    KeyUsageSignCert.ToBytes(),
	})

	if notBefore.IsZero() {
		validity.NotBefore = ZeroTime
	} else {
		validity.NotBefore = NewTime(notBefore)
	}
	if notAfter.IsZero() {
		validity.NotAfter = ZeroTime
	} else {
		validity.NotAfter = NewTime(notAfter)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ed25519.PrivateKey{}, err
	}
	cert := &Certificate{
		Version:      smolcertVersion,
		SerialNumber: 1,
		Issuer:       subject,
		Validity:     validity,
		Subject:      subject,
		PubKey:       pub,
		Extensions:   extensions,
		Signature:    nil,
	}
	cert, err = SignCertificate(cert, priv)
	return cert, priv, err
}
