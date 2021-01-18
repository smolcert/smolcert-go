package smolcert

import (
	"errors"
	"fmt"
)

const (
	// OIDKeyUsage specifies a KeyUsage extension. The ID right is arbitrary, we need to find a system...
	OIDKeyUsage uint64 = 0x10
)

// Extension represents a Certificate Extension as specified for X.509 certificates
type Extension struct {
	_ struct{} `cbor:",toarray"`

	OID      uint64 `cbor:"oid"`
	Critical bool   `cbor:"critical"`
	Value    []byte `cbor:"value"`
}

// KeyUsage limits for what the public key in a certificate can be used. Certain KeyUsages may be
// required for certain tasks (i.e. certificate validation, client identification etc.), but every
// Certificate can only specify one KeyUsage.
type KeyUsage uint8

// Defined KeyUsages
const (
	KeyUsageClientIdentification KeyUsage = 0x01
	KeyUsageServerIdentification KeyUsage = 0x02
	KeyUsageSignCert             KeyUsage = 0x03
)

// ToBytes returns the byte representation of a KeyUsage to be used as Value in an Extension
func (k KeyUsage) ToBytes() []byte {
	return []byte{byte(k)}
}

// String returns a String representation for logging and debugging
func (k KeyUsage) String() string {
	switch k {
	case KeyUsageClientIdentification:
		return "KeyUsageClientIdentification"
	case KeyUsageServerIdentification:
		return "KeyUsageServerIdentification"
	case KeyUsageSignCert:
		return "KeyUsageSignCert"
	default:
		return "Unknown KeyUsage"
	}
}

// ParseKeyUsage parses the KeyUsage from a byte slice, i.e. the Value of an Extension
func ParseKeyUsage(in []byte) (KeyUsage, error) {
	if len(in) > 1 || len(in) < 1 {
		return KeyUsage(0), fmt.Errorf("Unexpected length of input data when parsing KeyUsage (expected 1 byte, got %d bytes", len(in))
	}

	return KeyUsage(in[0]), nil
}

var (
	// ErrorExtensionNotFound is the expected error if a required extension can't be found
	ErrorExtensionNotFound = errors.New("Required extension not found")
)

// ValidateExtension is the definition of functions which can't be used with RequiresExtension to validate the
// the Value and Critical flag of an Extension
type ValidateExtension func(critical bool, val []byte) error

// ExpectKeyUsage ensures that the KeyUsage Extension specifies the expected KeyUsage
func ExpectKeyUsage(expectedKeyUsage KeyUsage) ValidateExtension {
	return func(critical bool, val []byte) error {
		if !critical {
			return errors.New("KeyUsage extension always needs to be declared critical")
		}
		parsedKeyUsage, err := ParseKeyUsage(val)
		if err != nil {
			return err
		}
		if parsedKeyUsage != expectedKeyUsage {
			return fmt.Errorf("Invalid KeyUsage. Expected %s, but this certificate specifies %s", expectedKeyUsage, parsedKeyUsage)
		}
		return nil
	}
}

// RequiresExtension checks if a certificate contains an Extension with a specific OID and validates the
// content of this extension via the ValidateExtension function
func RequiresExtension(cert *Certificate, oid uint64, validate ValidateExtension) error {
	for _, ext := range cert.Extensions {
		if ext.OID == oid {
			return validate(ext.Critical, ext.Value)
		}
	}
	return ErrorExtensionNotFound
}
