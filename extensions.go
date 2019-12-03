package smolcert

// Extension represents a Certificate Extension as specified for X.509 certificates
type Extension struct {
	_struct interface{} `codec:"-,toarray"`

	OID      uint64 `codec:"oid"`
	Critical bool   `codec:"critical"`
	Value    []byte `codec:"value"`
}
