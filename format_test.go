//go:build cddltest
// +build cddltest

package smolcert

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

// cddl certificates/spec.cddl validate certificates/cert.cbor

func TestValidGoCertificateFormat(t *testing.T) {
	notBefore := time.Now().UTC().Add(time.Hour * -12)
	notAfter := time.Now().UTC().Add(time.Hour * 12)

	pubKey := ed25519.PublicKey([]byte{0x00, 0x42, 0x23, 0x05})
	cert := &Certificate{
		Version:      smolcertVersion,
		Issuer:       "connctd",
		PubKey:       pubKey,
		SerialNumber: 12,
		Signature:    []byte{0x55, 0x42, 0x07},
		Subject:      "device",
		Extensions:   []Extension{},
		Validity:     &Validity{NotBefore: NewTime(notBefore), NotAfter: NewTime(notAfter)},
	}

	certFile, err := os.Create("./cert.cbor")
	require.NoError(t, err)
	defer certFile.Close()
	defer func() {
		require.NoError(t, os.Remove("cert.cbor"))
	}()
	require.NotZero(t, certFile)
	require.NoError(t, Serialize(cert, certFile))

	certFile.Close()
	cmd := exec.Command("cddl", "spec.cddl", "validate", "cert.cbor")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	require.NoError(t, err, "Certificate does not match specification")
}
