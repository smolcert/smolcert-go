package smolcert

import (
	"crypto/rand"
	"fmt"
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

func TestExpiredRootShouldntValidateClientCert(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -5)
	notAfter := now.Add(time.Minute * -1)

	rootCert, rootKey, err := SelfSignedCertificate("root", notBefore, notAfter, nil)
	require.NoError(t, err)

	clientCert, _, err := ClientCertificate("client1", 2,
		now.Add(time.Minute*-1), now.Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	pool := NewCertPool(rootCert)

	assert.Error(t, pool.Validate(clientCert))

	notBefore = now.Add(time.Minute)
	notAfter = now.Add(time.Hour)
	rootCert, rootKey, err = SelfSignedCertificate("root", notBefore, notAfter, nil)
	require.NoError(t, err)

	clientCert, _, err = ClientCertificate("client1", 2,
		now.Add(time.Minute*-1), now.Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	pool = NewCertPool(rootCert)

	assert.Error(t, pool.Validate(clientCert))
}

func TestRootCertDoesNotValidateWithoutCorrectKeyExtension(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootCert := &Certificate{
		SerialNumber: 1,
		Issuer:       "root",
		Validity: &Validity{
			NotBefore: NewTime(notBefore),
			NotAfter:  NewTime(notAfter),
		},
		Subject: "root",
		Extensions: []Extension{
			{
				OID:      OIDKeyUsage,
				Critical: false,
				Value:    KeyUsageClientIdentification.ToBytes(),
			},
		},
		PubKey: rootPub,
	}

	rootCert, err = SignCertificate(rootCert, rootKey)
	require.NoError(t, err)

	pool := NewCertPool()
	map[string]*Certificate(*pool)[rootCert.Subject] = rootCert

	clientCert, _, err := ClientCertificate("client1", 2, notBefore, notAfter, nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	assert.Error(t, pool.Validate(clientCert))
}

func TestIntermediateNeedsToBeSignedByRoot(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(time.Minute * -1)
	notAfter := now.Add(time.Hour)

	var lastCert *Certificate
	var lastKey ed25519.PrivateKey

	var intermediates []*Certificate

	for i := 0; i < 10; i++ {
		var err error
		if lastCert == nil {
			lastCert, lastKey, err = SelfSignedCertificate(fmt.Sprintf("intermediate%d", i), notBefore, notAfter, nil)
			intermediates = append(intermediates, lastCert)
			continue
		}

		pub, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		cert := &Certificate{
			SerialNumber: uint64(i + 1),
			Issuer:       lastCert.Subject,
			Validity: &Validity{
				NotBefore: NewTime(notBefore),
				NotAfter:  NewTime(notAfter),
			},
			Subject: fmt.Sprintf("intermediate%d", i),
			Extensions: []Extension{
				{
					OID:      OIDKeyUsage,
					Critical: true,
					Value:    KeyUsageSignCert.ToBytes(),
				},
			},
			PubKey: pub,
		}
		lastCert, err = SignCertificate(cert, lastKey)
		require.NoError(t, err)
		intermediates = append(intermediates, lastCert)
		lastKey = privKey
	}

	clientCert, _, err := ClientCertificate("client", 12, notBefore, notAfter, nil, lastKey, lastCert.Subject)
	require.NoError(t, err)
	intermediates = append(intermediates, clientCert)

	rootCert, _, err := SelfSignedCertificate("root", notBefore, notAfter, nil)
	require.NoError(t, err)

	pool := NewCertPool(rootCert)
	validatesClientCert, err := pool.ValidateBundle(intermediates)
	assert.Empty(t, validatesClientCert)
	assert.Error(t, err)
}
