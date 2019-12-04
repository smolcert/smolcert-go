/*
Package smolcert implements CBOR based certificates loosely based on the CBOR profile for X.509 certificates
(https://tools.ietf.org/id/draft-raza-ace-cbor-certificates-00.html)

Current ToDos:
- Limit key usage, not everyone should be able to sign keys
- probably more
*/
package smolcert

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/ed25519"
)

var (
	ch = &codec.CborHandle{
		TimeRFC3339: false,
	}
)

func init() {
	ch.EncodeOptions.Canonical = true
	ch.TimeNotBuiltin = false
}

// Certificate represents CBOR based certificates based on the provide spec.cddl
type Certificate struct {
	_struct interface{} `codec:"-,toarray"`

	SerialNumber uint64 `codec:"serial_number"`
	Issuer       string `codec:"issuer"`
	// NotBefore and NotAfter might be 0 to indicate to be ignored during validation
	Validity   *Validity         `codec:"validity,omitempty"`
	Subject    string            `codec:"subject"`
	PubKey     ed25519.PublicKey `codec:"public_key"`
	Extensions []Extension       `codec:"extensions"`
	Signature  []byte            `codec:"signature"`
}

// PublicKey returns the public key of this certificate as byte slice.
// Implements the github.com/connctd/noise.Identity interface.
func (c *Certificate) PublicKey() []byte {
	return c.PubKey
}

// Copy creates a deep copy of this certificate. This can be useful for operations where we need to change
// parts of the certificate, but need to continue working with an unaltered original.
func (c *Certificate) Copy() *Certificate {
	// Convert the public key to a byte slice and create a copy of this slice
	p2 := append([]byte{}, []byte(c.PubKey)...)
	c2 := &Certificate{
		SerialNumber: c.SerialNumber,
		Issuer:       c.Issuer,
		Validity: &Validity{
			NotBefore: c.Validity.NotBefore,
			NotAfter:  c.Validity.NotAfter,
		},
		Subject: c.Subject,
		// Reconstruct a public key from the byte slice copy we have created above
		PubKey:     ed25519.PublicKey(p2),
		Extensions: append([]Extension{}, c.Extensions...),
		Signature:  append([]byte{}, c.Signature...),
	}
	return c2
}

// Bytes returns the CBOR encoded form of the certificate as byte slice
func (c *Certificate) Bytes() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := Serialize(c, buf)
	return buf.Bytes(), err
}

// Time is a type to represent int encoded time stamps based on the elapsed seconds since epoch
type Time int64

// ZeroTime represent a zero timestamp which might indicate that this timestamp can be ignored
var ZeroTime = Time(0)

// NewTime creates a new Time from a given time.Time with second precision
func NewTime(now time.Time) *Time {
	unix := now.Unix()
	t := Time(unix)
	return &t
}

// StdTime returns a time.Time with second precision
func (t *Time) StdTime() time.Time {
	return time.Unix(int64(*t), 0)
}

// IsZero is true if this is a zero time
func (t *Time) IsZero() bool {
	return t == nil || int64(*t) == 0
}

// Validity represents the time constrained validity of a Certificate.
// NotBefore might be ZeroTime to ignore this constraint, same goes for NotAfter
type Validity struct {
	_struct interface{} `codec:"-,toarray"`

	NotBefore *Time `codec:"notBefore"`
	NotAfter  *Time `codec:"notAfter"`
}

// Parse parses a Certificate from an io.Reader
func Parse(r io.Reader) (cert *Certificate, err error) {
	dec := codec.NewDecoder(r, ch)

	cert = &Certificate{}
	if err := dec.Decode(cert); err != nil {
		return nil, err
	}

	return cert, err
}

// Serialize serializes a Certificate to an io.Writer
func Serialize(cert *Certificate, w io.Writer) (err error) {
	enc := codec.NewEncoder(w, ch)

	err = enc.Encode(cert)
	enc.Release()
	return
}
