//#![no_std]

use serde::de;
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::vec::Vec;

use ed25519_dalek::{Keypair, Signature, PublicKey};

mod errors;
mod pool;

pub use crate::errors::*;
pub use crate::pool::*;

type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Certificate {
  pub serial_number: u64,
  pub issuer: String,
  pub validity: Validity,
  pub subject: String,
  pub public_key: PublicKey,
  pub extensions: Vec<Extension>,
  pub signature: Bytes,
}

impl Certificate {
  pub fn new<'a>(
    serial_number: u64,
    issuer: &'a str,
    validity: Validity,
    subject: &'a str,
    extensions: Vec<Extension>,
    cert_keypair: &Keypair,
    signing_key: &Keypair,
  ) -> Result<Self> {
    let mut cert = Certificate {
      serial_number,
      issuer: issuer.to_owned(),
      validity,
      subject: subject.to_owned(),
      public_key: cert_keypair.public,
      extensions,
      signature: Bytes::from_slice(&[0;0][..]),
    };

    let cert_bytes = cert.to_vec()?;
    cert.signature = Bytes::from_slice(&signing_key.sign(&cert_bytes[..]).to_bytes()[..]);
    Ok(cert)
  }

  pub fn new_self_signed<'a>(
    serial_number: u64,
    issuer: &'a str,
    validity: Validity,
    subject: &'a str,
    extensions: Vec<Extension>,
    cert_keypair: &Keypair,
  ) -> Result<Self> {
    Certificate::new(serial_number,issuer,validity,subject,extensions, cert_keypair, cert_keypair)
  }

  pub fn to_vec(&self) -> Result<Vec<u8>> {
    let res_vec = serde_cbor::ser::to_vec_packed(self)?;
    Ok(res_vec)
  }

  pub fn from_vec(in_data: &[u8]) -> Result<Certificate> {
    let cert = serde_cbor::from_slice(in_data)?;
    Ok(cert)
  }

  pub fn verify_signature(&self, signing_key: &PublicKey) -> Result<()> {
    let mut cert_copy = self.clone();
    cert_copy.signature = Bytes::from_slice(&[0;0][..]);
    let cert_bytes = cert_copy.to_vec()?;
    let sig = Signature::from_bytes(&self.signature.data[..])?;
    let sig_res = signing_key.verify(&cert_bytes[..], &sig);
    match sig_res {
      Ok(_) => Ok(()),
      Err(e) => Err(Error::from(e)),
    }
  }
}

/*fn deserialize_slice<'de, D>(deserializer: D) -> core::result::Result<Vec<u8>, D::Error>
  where
    D: de::Deserializer<'de> ,
{
  let out: Vec<u8> = Vec::new();

  deserializer.deserialize_bytes(visitor: V)
}*/

impl Serialize for Certificate {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut seq = serializer.serialize_seq(Some(7))?;

    seq.serialize_element(&self.serial_number)?;
    seq.serialize_element(&self.issuer)?;
    seq.serialize_element(&self.validity)?;
    seq.serialize_element(&self.subject)?;

    // TODO I would like to avoid this copy operation
    //let pub_key_val = serde_cbor::value::Value::Bytes(self.public_key.data.clone());
    seq.serialize_element(&self.public_key)?;
    seq.serialize_element(&self.extensions)?;
    // TODO I would like to avoid this copy operation
    let signature_val = serde_cbor::value::Value::Bytes(self.signature.data.clone());
    seq.serialize_element(&signature_val)?;

    seq.end()
  }
}

struct CertificateVisitor;

impl<'de> de::Visitor<'de> for CertificateVisitor {
  type Value = Certificate;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str("a 7 element array representing a CBOR based certificate")
  }

  fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
  where
    A: de::SeqAccess<'de>,
  {
    if let Some(v) = seq.size_hint() {
      if v != 7 {
        return Err(de::Error::invalid_value(
          de::Unexpected::Unsigned(v as u64),
          &self,
        ));
      }
    }

    let cert = Certificate {
      serial_number: seq.next_element()?.unwrap_or(0),
      issuer: seq.next_element()?.unwrap_or_else(||"".to_string()),
      // TODO find a more elegant
      validity: seq.next_element()?.unwrap(),
      subject: seq.next_element()?.unwrap_or_else(||"".to_string()),
      public_key: seq.next_element()?.unwrap(),
      extensions: seq.next_element()?.unwrap(),
      signature: seq.next_element()?.unwrap_or_else(Bytes::empty),
    };
    Ok(cert)
  }
}

impl<'de> de::Deserialize<'de> for Certificate {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: de::Deserializer<'de>,
  {
    deserializer.deserialize_seq(CertificateVisitor)
  }
}

#[derive(Debug, Clone)]
pub struct Validity {
  pub not_before: u64,
  pub not_after: u64,
}

impl Serialize for Validity {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut seq = serializer.serialize_seq(Some(2))?;

    seq.serialize_element(&self.not_before)?;
    seq.serialize_element(&self.not_after)?;

    seq.end()
  }
}

struct ValidityVisitor;

impl<'de> de::Visitor<'de> for ValidityVisitor {
  type Value = Validity;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str("a two value array")
  }

  fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
  where
    A: de::SeqAccess<'de>,
  {
    if let Some(v) = seq.size_hint() {
      if v != 2 {
        return Err(de::Error::invalid_value(
          de::Unexpected::Unsigned(v as u64),
          &self,
        ));
      }
    }

    let validity = Validity {
      not_before: seq.next_element()?.unwrap_or(0),
      not_after: seq.next_element()?.unwrap_or(0),
    };

    Ok(validity)
  }
}

impl<'de> de::Deserialize<'de> for Validity {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: de::Deserializer<'de>,
  {
    deserializer.deserialize_seq(ValidityVisitor)
  }
}

#[derive(Debug, Clone)]
pub struct Extension {
  pub oid: u64,
  pub critical: bool,
  pub value: Vec<u8>,
}

impl Serialize for Extension {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut seq = serializer.serialize_seq(Some(3))?;

    seq.serialize_element(&self.oid)?;
    seq.serialize_element(&self.critical)?;
    // TODO I would like to avoid this copy operation
    let value_val = serde_cbor::value::Value::Bytes(self.value.clone());
    seq.serialize_element(&value_val)?;

    seq.end()
  }
}

struct ExtensionVisitor;

impl<'de> de::Visitor<'de> for ExtensionVisitor {
  type Value = Extension;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str("a 3 element array representing an Extension")
  }

  fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
  where
    A: de::SeqAccess<'de>,
  {
    if let Some(v) = seq.size_hint() {
      if v != 3 {
        return Err(de::Error::invalid_value(
          de::Unexpected::Unsigned(v as u64),
          &self,
        ));
      }
    }
    let ext = Extension {
      oid: seq.next_element()?.unwrap_or(0),
      critical: seq.next_element()?.unwrap_or(true),
      value: seq.next_element()?.unwrap(),
    };
    Ok(ext)
  }
}

impl<'de> Deserialize<'de> for Extension {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: de::Deserializer<'de>,
  {
    deserializer.deserialize_seq(ExtensionVisitor)
  }
}

#[derive(Debug, Clone)]
pub struct Bytes {
  data: Vec<u8>,
}

impl Bytes {
  pub fn from_vec(data: Vec<u8>) -> Bytes {
    Bytes{
      data,
    }
  }

  pub fn from_slice(data: &[u8]) -> Bytes {
    Bytes{
      data: data.to_vec(),
    }
  }

  pub fn empty() -> Bytes {
    Bytes{
      data: Vec::new(),
    }
  }
}

impl<'de> de::Deserialize<'de> for Bytes {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: de::Deserializer<'de>,
  {
    deserializer.deserialize_seq(ByteArrayVisitor)
  }
}

struct ByteArrayVisitor;

impl<'de> de::Visitor<'de> for ByteArrayVisitor {
  type Value = Bytes;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str("a byte array")
  }

  fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
  where
    E: de::Error,
  {
    Ok(Bytes { data: v.to_vec() })
  }
}

#[cfg(test)]
mod tests {

  use super::*;

  use rand::rngs::OsRng;
  use ed25519_dalek::{Keypair, Signature, PublicKey};

  #[test]
  fn certificate_deserialize() {
    let cert = Certificate::from_vec(EXPECTED_CERT_BYTES).unwrap();
    assert_eq!(12, cert.serial_number);
    assert_eq!("connctd", cert.issuer);
    assert_eq!(1_576_108_145, cert.validity.not_after);
    assert_eq!(1_576_021_745, cert.validity.not_before);
    assert_eq!("connctd", cert.subject);
  }

  #[test]
  fn certificate_serialize() {
    let pub_key = PublicKey::from_bytes(EXPECTED_CERT_PUB_KEY).unwrap();
    let signature: &[u8] = &[4, 5, 6, 7];
    let extensions: Vec<Extension> = vec![];

    let cert = Certificate{
      serial_number: 12,
      issuer: "fooissuer".to_owned(),
      validity: Validity {
        not_after: 13,
        not_before: 2,
      },
      subject: "barsubject".to_owned(),
      public_key: pub_key,
      extensions,
      signature: Bytes::from_slice(&signature),
    };

    let res = cert.to_vec();
    assert!(!res.is_err());
  }

  #[test]
  fn self_signed() {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let extensions: Vec<Extension> = vec![];

    let cert = Certificate::new_self_signed(12, "connctd self signed", Validity {
      not_after: 13,
      not_before: 2,
    }, "subject self", extensions, &keypair).unwrap();
    cert.verify_signature(&keypair.public).unwrap();
  }

  static EXPECTED_CERT_BYTES: &[u8] = &[
    0x87,0x0c,0x67,0x63,0x6f,0x6e,0x6e,0x63,0x74,0x64,0x82,0x1a,
    0x5d,0xf0,0x2e,0xf1,0x1a,0x5d,0xf1,0x80,0x71,0x67,0x63,0x6f,
    0x6e,0x6e,0x63,0x74,0x64,0x58,0x20,0x95,0x38,0xee,0xf6,0x5d,
    0x12,0x34,0xa6,0x37,0x33,0x45,0x13,0x18,0x06,0xf8,0x00,0x6c,
    0x4c,0x6c,0x81,0xc8,0xdb,0x58,0x19,0x24,0x18,0x9f,0x82,0x89,
    0xdd,0x7c,0x43,0x80,0x58,0x40,0xd9,0xde,0x51,0x67,0x32,0x92,
    0xb3,0xed,0x69,0xaa,0x83,0xdd,0xd4,0xf2,0x04,0xe2,0x5c,0x5e,
    0xd2,0x5f,0x7d,0x43,0xa0,0x33,0x99,0x0e,0x52,0x33,0x9d,0x08,
    0x89,0x77,0xd5,0x4c,0x1b,0x9d,0x53,0x31,0x42,0x03,0xb5,0x1d,
    0xf1,0x38,0x78,0x85,0x06,0x87,0xbf,0x58,0xe6,0x19,0xb0,0xf7,
    0xa8,0xfc,0xd8,0x29,0x57,0x90,0x0c,0xf7,0x82,0x01
  ];

  static EXPECTED_CERT_PUB_KEY: &[u8] = &[
    0x95, 0x38, 0xee, 0xf6, 0x5d, 0x12, 0x34, 0xa6, 0x37, 0x33, 
    0x45, 0x13, 0x18, 0x6, 0xf8, 0x0, 0x6c, 0x4c, 0x6c, 0x81, 
    0xc8, 0xdb, 0x58, 0x19, 0x24, 0x18, 0x9f, 0x82, 0x89, 0xdd, 0x7c, 0x43
  ];

  static EXPECTED_CERT_SIGNATURE: &[u8] = &[
    0xd9, 0xde, 0x51, 0x67, 0x32, 0x92, 0xb3, 0xed, 0x69, 0xaa, 
    0x83, 0xdd, 0xd4, 0xf2, 0x4, 0xe2, 0x5c, 0x5e, 0xd2, 0x5f, 
    0x7d, 0x43, 0xa0, 0x33, 0x99, 0xe, 0x52, 0x33, 0x9d, 0x8, 
    0x89, 0x77, 0xd5, 0x4c, 0x1b, 0x9d, 0x53, 0x31, 0x42, 0x3, 0xb5, 
    0x1d, 0xf1, 0x38, 0x78, 0x85, 0x6, 0x87, 0xbf, 0x58, 0xe6, 0x19, 
    0xb0, 0xf7, 0xa8, 0xfc, 0xd8, 0x29, 0x57, 0x90, 0xc, 0xf7, 0x82, 0x1
  ];

  #[test]
  fn correct_format() {
    let pub_key = PublicKey::from_bytes(EXPECTED_CERT_PUB_KEY).unwrap();
    let extensions: Vec<Extension> = vec![];

    let cert = Certificate{
      serial_number: 12,
      issuer: "connctd".to_owned(),
      validity: Validity {
        not_after: 1_576_108_145,
        not_before: 1_576_021_745,
      },
      subject: "connctd".to_owned(),
      public_key: pub_key,
      extensions,
      signature: Bytes::from_slice(EXPECTED_CERT_SIGNATURE),
    };

    let res = cert.to_vec();
    assert!(res.is_ok());
    let cert_bytes = &res.unwrap()[..];
    assert_eq!(
      EXPECTED_CERT_BYTES, cert_bytes,
      "The rust version didn't serialize as expected {:02x?} (go version: \n{:02x?}",
      cert_bytes, EXPECTED_CERT_BYTES,
    );
  }
}

