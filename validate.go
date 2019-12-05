package smolcert

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ed25519"
)

// CertPool is a pool of root certificates which can be used to validate a certificate
type CertPool map[string]*Certificate

// NewCertPool creates a new CertPool from a group of root certificates
func NewCertPool(rootCerts ...*Certificate) *CertPool {
	p := make(CertPool)
	for _, c := range rootCerts {
		if err := RequiresExtension(c, OIDKeyUsage, ExpectKeyUsage(KeyUsageSignCert)); err != nil {
			// Ignore certificates which do not specify to be used to sign certificates silently
			continue
		}
		p[c.Subject] = c
	}
	return &p
}

// Validate takes a certificate, checks if the issuer is known to the CertPool, validates
// the issuer certificate and then validates the given certificate against the issuer certificate
func (c *CertPool) Validate(cert *Certificate) error {

	issuerCert, exists := (*c)[cert.Issuer]
	// A nil root cert shouldn't happen, but who knows
	if !exists || issuerCert == nil {
		return errors.New("certificate is not signed by a known issuer")
	}
	// Validate the issuer cert, might be invalid too (expired etc.)
	if err := validateCertificate(issuerCert, issuerCert.PubKey); err != nil {
		return fmt.Errorf("Error validating issuing root certificate: %w", err)
	}
	if err := RequiresExtension(issuerCert, OIDKeyUsage, ExpectKeyUsage(KeyUsageSignCert)); err != nil {
		return fmt.Errorf("Trusted root certificates need to have the KeyUsage SignCert: %w", err)
	}

	return validateCertificate(cert, issuerCert.PubKey)
}

// ValidateBundle validates a given bundle of certificates. It tries to build a chain of certificates
// within the given bundle. Uses the leaf as the client certificate and tries to validate the top
// certificate against the CertPool.
func (c *CertPool) ValidateBundle(certBundle []*Certificate) (clientCert *Certificate, err error) {
	// FIXME when we have defined extensions, validate capabilities of certificates through extensions
	issuerMap := make(map[string]*Certificate)
	subjectMap := make(map[string]*Certificate)
	for _, cert := range certBundle {
		issuerMap[cert.Issuer] = cert
		subjectMap[cert.Subject] = cert
	}

	var intermediateCerts []*Certificate
	for _, cert := range certBundle {
		if _, found := issuerMap[cert.Subject]; found {
			intermediateCerts = append(intermediateCerts, cert)
			continue
		} else {
			clientCert = cert
		}
	}

	if clientCert == nil {
		return nil, errors.New("Can't find non-intermediate certificate in certificate chain")
	}

	if clientIssuer, found := subjectMap[clientCert.Issuer]; found {
		if err := validateCertificate(clientCert, clientIssuer.PubKey); err != nil {
			return nil, err
		}
	} else {
		// Might be that the certificate is already trusted through the current pool
		if err = c.Validate(clientCert); err == nil {
			return clientCert, nil
		}
		return nil, errors.New("No issuer for the client certificate was found in the intermediate certificates: " + err.Error())
	}

	var chainTopCert *Certificate
	// Validate the chain of intermediate certs
	for _, cert := range intermediateCerts {
		if err := RequiresExtension(cert, OIDKeyUsage, ExpectKeyUsage(KeyUsageSignCert)); err != nil {
			return nil, fmt.Errorf("Intermediate certificate (subject '%s', does not possess KeyUsage SignCert: %w", cert.Subject, err)
		}
		if issuerCert, exists := subjectMap[cert.Issuer]; exists {
			if err := validateCertificate(cert, issuerCert.PubKey); err != nil {
				return nil, errors.New("Validation error in chain of intermediate certificates")
			}
		} else {
			chainTopCert = cert
		}
	}

	if chainTopCert == nil {
		return nil, errors.New("The intermediate chain is self signed and not signed by one of the root certs of this pool")
	}
	if err := c.Validate(chainTopCert); err != nil {
		return nil, err
	}
	return clientCert, nil
}

func validateValidity(cert *Certificate) error {
	nowUnix := time.Now().Unix()
	if !cert.Validity.NotBefore.IsZero() {
		if int64(cert.Validity.NotBefore) > nowUnix {
			return fmt.Errorf("certificate is not valid before %s (notBefore %d, now %d)",
				cert.Validity.NotBefore.StdTime().Format(time.RFC3339), cert.Validity.NotBefore, nowUnix)
		}
	}

	if !cert.Validity.NotAfter.IsZero() {
		if int64(cert.Validity.NotAfter) < nowUnix {
			return fmt.Errorf("certificate is not valid since %s", cert.Validity.NotAfter.StdTime().Format(time.RFC3339))
		}
	}
	return nil
}

func checkForDoubleExtensions(cert *Certificate) error {
	seen := make(map[uint64]bool)

	for _, ext := range cert.Extensions {
		if seen[ext.OID] {
			return fmt.Errorf("This certificate contains a repeated extension (OID: %X) which is invalid", ext.OID)
		}
		seen[ext.OID] = true
	}
	return nil
}

func validateCertificate(origCert *Certificate, pubKey ed25519.PublicKey) error {
	cert := origCert.Copy()
	if err := validateValidity(cert); err != nil {
		return err
	}
	if err := checkForDoubleExtensions(cert); err != nil {
		return err
	}
	sig := cert.Signature

	cert.Signature = nil
	certBytes, err := cert.Bytes()

	if err != nil {
		return errors.New("Failed to serialize certificate for validation")
	}
	if !ed25519.Verify(pubKey, certBytes, sig) {
		return errors.New("Signature validation failed")
	}
	return nil
}
