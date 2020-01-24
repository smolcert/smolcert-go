//#![no_std]
#![cfg_attr(not(feature="std"), no_std)] 

#[cfg(feature="std")]
use std::fmt;
use std::vec::Vec;
use std::fs::File;
use std::path::Path;

use serde::de;
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};


use ed25519_dalek::{Keypair, Signature, PublicKey};

pub mod errors;
pub mod pool;
pub mod extensions;

pub use crate::errors::*;
pub use crate::pool::*;
pub use crate::extensions::*;

type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Certificate
{
  pub serial_number: u64,
  pub issuer: String,
  pub validity: Validity,
  pub subject: String,
  pub public_key: PublicKey,
  pub extensions: Vec<Extension>,
  pub signature: Option<Signature>,
}

impl Certificate
{
  pub fn new(
    serial_number: u64,
    issuer: String,
    validity: Validity,
    subject: String,
    exts: Vec<Extension>,
    cert_keypair: &Keypair,
    signing_key: &Keypair,
  ) -> Result<Self> {
    let mut cert = Certificate {
      serial_number,
      issuer,
      validity,
      subject,
      public_key: cert_keypair.public,
      extensions: exts,
      signature: None,
    };

    let cert_bytes = cert.to_vec()?;
    cert.signature = Some(signing_key.sign(&cert_bytes[..]));
    Ok(cert)
  }

  pub fn new_self_signed(
    serial_number: u64,
    issuer: String,
    validity: Validity,
    subject: String,
    extensions: Vec<Extension>,
    cert_keypair: &Keypair,
  ) -> Result<Self> {
    Certificate::new(serial_number,issuer,validity,subject, extensions, cert_keypair, cert_keypair)
  }

  pub fn to_vec(&self) -> Result<Vec<u8>> {
    let res_vec = serde_cbor::ser::to_vec_packed(&self)?;
    Ok(res_vec)
  }

  pub fn from_slice(in_data: &[u8]) -> Result<Certificate> {
    let cert = serde_cbor::from_slice(in_data)?;
    Ok(cert)
  }

  #[cfg(feature="std")]
  pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Certificate> {
    let mut in_file = File::open(path)?;
    let cert = serde_cbor::from_reader(in_file)?;
    Ok(cert)
  }

  pub fn verify_signature(&mut self, signing_key: &PublicKey) -> Result<()> {
    //let mut cert_copy = self.clone().to_owned();
    let signature = self.signature;
    self.signature = None;
    let cert_bytes = self.to_vec()?;
    self.signature = signature;
    match self.signature {
      Some(sig) => {
        let sig_res = signing_key.verify(&cert_bytes[..], &sig);
        match sig_res {
          Ok(_) => Ok(()),
          Err(e) => Err(Error::from(e)),
        }
      },
      None => Err(Error{
        code: ErrorCode::ValidationError(ValidationErrorCode::SignatureError),
      })
    } 
  }
}

impl Serialize for Certificate
{
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut seq = serializer.serialize_seq(Some(7))?;

    seq.serialize_element(&self.serial_number)?;
    seq.serialize_element(&self.issuer)?;
    seq.serialize_element(&self.validity)?;
    seq.serialize_element(&self.subject)?;

    seq.serialize_element(&self.public_key)?;
    seq.serialize_element(&self.extensions)?;
    seq.serialize_element(&self.signature)?;

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

    let serial_number : u64= seq.next_element()?.unwrap_or(0);
    let issuer : String = seq.next_element()?.unwrap_or_else(||"".to_string());
    let validity : Validity =  seq.next_element()?.unwrap();
    let subject : String = seq.next_element()?.unwrap_or_else(||"".to_string());
    let public_key : PublicKey = seq.next_element()?.unwrap();
    let extensions : Vec<Extension> = seq.next_element()?.unwrap();
    let signature : Option<Signature> = seq.next_element()?.unwrap_or_else(||None);

    let cert : Certificate = Certificate {
      serial_number,
      issuer,
      // TODO find a more elegant way
      validity,
      subject,
      public_key,
      extensions,
      signature,
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

#[derive(Debug, Clone, Copy)]
pub struct Validity {
  pub not_before: u64,
  pub not_after: u64,
}

impl Validity {
  pub fn new(not_before: u64, not_after: u64) -> Self {
    Validity{
      not_after,
      not_before,
    }
  }

  pub fn empty() -> Self {
    Validity{
      not_after: 0,
      not_before: 0,
    }
  }

  pub fn is_empty(&self) -> bool {
    self.not_after == 0 && self.not_before == 0 
  }

  pub fn is_valid(&self, now: u64) -> Result<()> {
    if self.is_empty() {
      return Ok(())
    }
    if self.not_before < now || self.not_after < now {
      return Err(Error{
        code: ErrorCode::ValidationError(ValidationErrorCode::ValidityError{
          not_before: self.not_before,
          not_after: self.not_after,
        }),
      })
    }
    Ok(())
  }
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

#[cfg(test)]
mod tests {

  use super::*;

  use rand::rngs::OsRng;
  use ed25519_dalek::{Keypair, Signature, PublicKey};

  #[test]
  fn certificate_deserialize() {
    let cert = Certificate::from_slice(EXPECTED_CERT_BYTES).unwrap();
    assert_eq!(12, cert.serial_number);
    assert_eq!("connctd", cert.issuer);
    assert_eq!(1_576_108_145, cert.validity.not_after);
    assert_eq!(1_576_021_745, cert.validity.not_before);
    assert_eq!("connctd", cert.subject);
  }

  #[test]
  fn certificate_serialize() {
    let pub_key = PublicKey::from_bytes(EXPECTED_CERT_PUB_KEY).unwrap();
    let signature = Signature::from_bytes(EXPECTED_CERT_SIGNATURE).unwrap();
    let extensions: Vec<Extension> = vec![];
    

    let cert = Certificate{
      serial_number: 12,
      issuer: "fooissuer".to_string(),
      validity: Validity {
        not_after: 13,
        not_before: 2,
      },
      subject: "barsubject".to_string(),
      public_key: pub_key,
      extensions,
      signature: Some(signature),
    };

    let res = cert.to_vec();
    assert!(!res.is_err());
  }

  #[test]
  fn self_signed() {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let extensions: Vec<Extension> = vec![];

    let mut cert = Certificate::new_self_signed(12, "connctd self signed".to_string(), Validity {
      not_after: 13,
      not_before: 2,
    }, "subject self".to_string(), extensions, &keypair).unwrap();
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
    let signature = Signature::from_bytes(EXPECTED_CERT_SIGNATURE).unwrap();

    let cert = Certificate{
      serial_number: 12,
      issuer: "connctd".to_string(),
      validity: Validity {
        not_after: 1_576_108_145,
        not_before: 1_576_021_745,
      },
      subject: "connctd".to_string(),
      public_key: pub_key,
      extensions,
      signature: Some(signature),
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

