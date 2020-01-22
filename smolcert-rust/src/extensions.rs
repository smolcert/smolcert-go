use super::*;

use serde::{Deserialize, Serialize};

pub type OID = u64;

pub const OID_KEYUSAGE: OID = 0x10;

pub type KeyUsage = u8;

pub const CLIENT_IDENTIFICATION: KeyUsage = 0x01;
pub const SERVER_IDENTIFICATION: KeyUsage = 0x02;
pub const SIGN_CERTIFICATE: KeyUsage = 0x03;

#[derive(Debug, Clone)]
pub enum Extension {
  KeyUsage(KeyUsage),
  Unknown{
    oid: OID,
    value: Vec<u8>,
    critical: bool,
  },
}

impl Extension {
 pub fn oid(&self) -> OID {
   match self {
     Extension::KeyUsage(_) => {
       OID_KEYUSAGE
     },
     Extension::Unknown{oid, value: _value, critical: _critical} => {
       *oid
     }
   }
 }

  pub fn critical(&self) -> bool {
    match self {
      Extension::KeyUsage(_) => {
        true
      }
      Extension::Unknown{oid: _oid, value: _value, critical} => {
        *critical
      }
    }
  }

  pub fn value(&self) -> Vec<u8> {
    match self {
      Extension::KeyUsage(val) => {
        vec![*val as u8]
      }
      Extension::Unknown{oid: _oid, value, critical: _critical} => {
        value.to_vec()
      }
    }
  }
}

impl Serialize for Extension
{
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut seq = serializer.serialize_seq(Some(3))?;

    seq.serialize_element(&self.oid())?;
    seq.serialize_element(&self.critical())?;
    // TODO I would like to avoid this copy operation
    let value_val = serde_cbor::value::Value::Bytes(self.value());
    seq.serialize_element(&value_val)?;

    seq.end()
  }
}

struct ExtensionVisitor;

impl<'de> de::Visitor<'de> for ExtensionVisitor  
{
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
    let oid: OID = seq.next_element()?.unwrap_or(0);
    let critical : bool = seq.next_element()?.unwrap_or(true);
    let value : Vec<u8> = seq.next_element()?.unwrap_or_else(||vec![0x0]);

    let ext = match oid {
      OID_KEYUSAGE => {
        let val: KeyUsage = match value[0] {
          CLIENT_IDENTIFICATION => CLIENT_IDENTIFICATION,
          SERVER_IDENTIFICATION => SERVER_IDENTIFICATION,
          SIGN_CERTIFICATE => SIGN_CERTIFICATE,
          v => return Err(de::Error::invalid_value(
            de::Unexpected::Unsigned(v as u64),
            &self,
          ))
        };
        Extension::KeyUsage(val)
      },
      _ => {
        Extension::Unknown{
          value,
          oid,
          critical,
        }
      }
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