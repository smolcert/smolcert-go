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
	_struct interface{} `codec:"-,toarray"`

	OID      uint64 `codec:"oid"`
	Critical bool   `codec:"critical"`
	Value    []byte `codec:"value"`
}

type KeyUsage uint8

const (
	KeyUsageClientIdentification KeyUsage = 0x01
	KeyUsageServerIdentification KeyUsage = 0x02
	KeyUsageSignCert             KeyUsage = 0x03
)

func (k KeyUsage) ToBytes() []byte {
	return []byte{byte(k)}
}

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

func ParseKeyUsage(in []byte) (KeyUsage, error) {
	if len(in) > 1 || len(in) < 1 {
		return KeyUsage(0), fmt.Errorf("Unexpected length of input data when parsing KeyUsage (expected 1 byte, got %d bytes", len(in))
	}

	return KeyUsage(in[0]), nil
}

var (
	ErrorExtensionNotFound = errors.New("Required extension not found")
)

type ValidateExtension func(critical bool, val []byte) error

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

func RequiresExtension(cert *Certificate, oid uint64, validate ValidateExtension) error {
	for _, ext := range cert.Extensions {
		if ext.OID == oid {
			return validate(ext.Critical, ext.Value)
		}
	}
	return ErrorExtensionNotFound
}
