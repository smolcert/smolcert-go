package smolcert

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
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
