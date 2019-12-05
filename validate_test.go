package smolcert

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestExtensionDubletteInRootCert(t *testing.T) {
	someOID := uint64(42)
	extensionValue := []byte("Trying to do something sneaky")

	extensions := []Extension{
		{
			OID:      someOID,
			Critical: true,
			Value:    extensionValue,
		},
		{
			OID:      someOID,
			Critical: false,
			Value:    extensionValue,
		},
		{
			OID:      someOID,
			Critical: true,
			Value:    extensionValue,
		},
	}

	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	rootCert, rootKey, err := SelfSignedCertificate("root", notBefore, notAfter, extensions)
	require.NoError(t, err)

	rootPool := NewCertPool(rootCert)

	clientCert, _, err := ClientCertificate("client1", 2, notBefore, notAfter, extensions, rootKey, rootCert.Subject)
	require.NoError(t, err)

	assert.Error(t, rootPool.Validate(clientCert))
}

func TestSneakKeyUsageInClientCert(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	rootCert, rootKey, err := SelfSignedCertificate("root", notBefore, notAfter, nil)
	require.NoError(t, err)

	extensions := []Extension{
		{
			OID:      OIDKeyUsage,
			Critical: true,
			Value:    KeyUsageSignCert.ToBytes(),
		},
		{
			OID:      OIDKeyUsage,
			Critical: true,
			Value:    KeyUsageClientIdentification.ToBytes(),
		},
	}

	clientCert, _, err := SignedCertificate("sneakyClient", 42, notBefore, notAfter, extensions, rootKey, rootCert.Subject)
	require.NoError(t, err)

	certPool := NewCertPool(rootCert)
	assert.Error(t, certPool.Validate(clientCert))
}

func TestCertPoolRequiresCorrectKeyUsage(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootCert := &Certificate{
		SerialNumber: 1,
		Issuer:       "EvilMe",
		Validity: &Validity{
			NotBefore: NewTime(notBefore),
			NotAfter:  NewTime(notAfter),
		},
		Subject: "EvilMe",
		Extensions: []Extension{
			{
				OID:      OIDKeyUsage,
				Critical: false,
				Value:    KeyUsageServerIdentification.ToBytes(),
			},
		},
		PubKey: rootPub,
	}

	rootCert, err = SignCertificate(rootCert, rootKey)
	require.NoError(t, err)

	clientCert, _, err := ClientCertificate("trustfulClient", 42, notBefore, notAfter, nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	pool := NewCertPool(rootCert)
	assert.Error(t, pool.Validate(clientCert))
}

func TestIntermediateCertsHaveCorrectKeyUsage(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	intermediateExtensions := []Extension{
		{
			OID:      OIDKeyUsage,
			Critical: true,
			Value:    KeyUsageSignCert.ToBytes(),
		},
	}

	invalidIntermediateExtensions := []Extension{
		{
			OID:      OIDKeyUsage,
			Critical: true,
			Value:    KeyUsageClientIdentification.ToBytes(),
		},
	}

	rootCert, rootKey, err := SelfSignedCertificate("root", notBefore, notAfter, nil)
	require.NoError(t, err)

	intermediateCert1, imKey1, err := SignedCertificate("intermediate1", 2,
		notBefore, notAfter, invalidIntermediateExtensions, rootKey, rootCert.Subject)
	require.NoError(t, err)

	intermediateCert2, imKey2, err := SignedCertificate("intermediate2", 3,
		notBefore, notAfter, intermediateExtensions, imKey1, intermediateCert1.Subject)
	require.NoError(t, err)

	clientCert, _, err := ClientCertificate("client1", 4, notBefore, notAfter, nil, imKey2, intermediateCert2.Subject)
	require.NoError(t, err)

	certBundle := []*Certificate{intermediateCert1, intermediateCert2, clientCert}
	pool := NewCertPool(rootCert)

	validatesClientCert, err := pool.ValidateBundle(certBundle)
	assert.Error(t, err)
	assert.Empty(t, validatesClientCert)
}
