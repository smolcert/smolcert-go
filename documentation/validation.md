# Validation rules

Certificates need adhere to a set of rules to be considered valid. This is necessary
to avoid misuse of certificates and security issues due to unexpected results.
Certificates can either be self signed or signed by the private key of another certificate.

# Common validation rules

* The field `subject` must not be empty.
* The field `issuer` must not be emtpy.
* There must be no two extensions of the same type.
* If `NotBefore` is not zero it must be checked that `NotBefore` is smaller than
  the current time in UTC represented in seconds since epoch.
* If `NotAfter` is not zero it must be checked `NotAfter` is larger than the current
  time in UTC represented in seconds since epoch.
* The serial number must be greater than 0. 0 is considered an invalid value.
* The field public key must not be empty and be a valid representation of an
  ed25519 public key.
* The field signature must not be empty and be a valid representation of an ed25519
  signature.
* Every certificate must have at least one extension of the type `KeyUsage`, marked as
  critical.
* There must be no unknown Extensions present. If a validator encounters an unknown extension
  the certificate is considered invalid.


## Self Signed Certificates

A self signed certificate can only be used as a trust anchor. A self signed certificate is only
considered valid if the following conditions are fulfilled:

* The subject name equals the exact issuer name
* The signature can be validated with the public key of the certificate
* The certificate must have an extension of type `KeyUsage` with the value `SignCert`
  because self signed certificates can only be used as trust anchors.

## Signed Certificates

A signed certificate is signed by the private key of another certificate. These are usually
the certificates used at the client or server side or an intermediate in the trust chain. The
validator needs to have a collection of certificates used as trust anchor.

* The certificate must have a subject field different from the issuer field
* The certificate must have an extension of type `KeyUsage`.
  * If the value is `SignCert` the certificate is used as an intermediate in the trust chain
    and must not be used to verify identities of a client or server
  * If the value is `ServerIdentification` this certificate must only be used to verify
    the identity of a server/responder
  * If the value is `ClientIdentification` this certificate must only be used to verify
    the identity of a client/initiator
* The validator must have a certificate in his collection of trust anchors whose subject field
  is equal to the issuer field.
* The certificates signature must be validated by the public key of the trust anchor with the
  same subject field as this certificates issuer field
