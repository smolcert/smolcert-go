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
