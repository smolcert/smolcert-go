package smolcert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateKeyUsages(t *testing.T) {
	testTable := []struct {
		cert             *Certificate
		expectedKeyUsage KeyUsage
		valid            bool
	}{
		{
			cert: &Certificate{
				Extensions: []Extension{
					Extension{
						OID:      OIDKeyUsage,
						Critical: true,
						Value:    KeyUsageClientIdentification.ToBytes(),
					},
				},
			},
			expectedKeyUsage: KeyUsageClientIdentification,
			valid:            true,
		},

		{
			cert: &Certificate{
				Extensions: []Extension{
					Extension{
						OID:      OIDKeyUsage,
						Critical: true,
						Value:    KeyUsageClientIdentification.ToBytes(),
					},
				},
			},
			expectedKeyUsage: KeyUsageSignCert,
			valid:            false,
		},

		{
			cert: &Certificate{
				Extensions: []Extension{
					Extension{
						OID:      OIDKeyUsage,
						Critical: true,
						Value:    KeyUsageClientIdentification.ToBytes(),
					},
				},
			},
			expectedKeyUsage: KeyUsageServerIdentification,
			valid:            false,
		},

		{
			cert: &Certificate{
				Extensions: []Extension{},
			},
			expectedKeyUsage: KeyUsageClientIdentification,
			valid:            false,
		},
	}

	for _, tt := range testTable {
		err := RequiresExtension(tt.cert, OIDKeyUsage, ExpectKeyUsage(tt.expectedKeyUsage))
		assert.Equal(t, err == nil, tt.valid)
	}
}
