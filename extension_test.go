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

func TestEnsureExtension(t *testing.T) {
	testtable := []struct {
		extensions    []Extension
		expectedCount int
		ensured       Extension
	}{
		{
			extensions: []Extension{
				{
					OID:      12,
					Critical: false,
				},
				{
					OID:      13,
					Critical: false,
				},
			},
			expectedCount: 3,
			ensured: Extension{
				OID: 14,
			},
		},

		{
			extensions: []Extension{
				{
					OID:      12,
					Critical: false,
				},
				{
					OID:      13,
					Critical: false,
				},
			},
			expectedCount: 2,
			ensured: Extension{
				OID: 12,
			},
		},
		{
			extensions:    []Extension{},
			expectedCount: 1,
			ensured: Extension{
				OID: 14,
			},
		},
	}

	for i, tt := range testtable {
		extensions := ensureExtension(tt.extensions, tt.ensured)
		assert.Len(t, extensions, tt.expectedCount, "Test iteration %d", i)
	}
}
