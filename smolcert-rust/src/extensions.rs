use super::*;

#[cfg(feature = "std")]
use std::fmt;

use serde::{Deserialize, Serialize};

pub type OID = u64;

pub const OID_KEYUSAGE: OID = 0x10;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
pub enum KeyUsage {
    ClientIdentification = 0x01,
    ServerIdentification = 0x02,
    SignCertificate = 0x03,
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyUsage::ClientIdentification => write!(f, "Client Identification"),
            KeyUsage::ServerIdentification => write!(f, "Server Identification"),
            KeyUsage::SignCertificate => write!(f, "Sign Certificates"),
        }
    }
}

impl ExtensionValue<'_> for KeyUsage {}

pub trait ExtensionValue<'de>: Serialize + Deserialize<'de> {
    /* #[cfg(feature = "std")]
    fn as_bytes(&self) -> Vec<u8>;

    #[cfg(feature = "std")]
    fn from_bytes(data: &[u8]) -> Result<Self>;*/
}

#[derive(Debug, Clone)]
pub enum Extension {
    KeyUsage(KeyUsage),
    Unknown {
        oid: OID,
        value: Vec<u8>,
        critical: bool,
    },
}

impl Extension {
    pub fn oid(&self) -> OID {
        match self {
            Extension::KeyUsage(_) => OID_KEYUSAGE,
            Extension::Unknown {
                oid,
                value: _value,
                critical: _critical,
            } => *oid,
        }
    }

    pub fn critical(&self) -> bool {
        match self {
            Extension::KeyUsage(_) => true,
            Extension::Unknown {
                oid: _oid,
                value: _value,
                critical,
            } => *critical,
        }
    }

    pub fn value(&self) -> Vec<u8> {
        match self {
            Extension::KeyUsage(val) => vec![*val as u8],
            Extension::Unknown {
                oid: _oid,
                value,
                critical: _critical,
            } => value.to_vec(),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Extension::KeyUsage(_v) => write!(f, "Key usage (critical extension)"),
            Extension::Unknown {
                oid,
                critical,
                value,
            } => write!(
                f,
                "Unknown extension: OID {}, critical {}, value {:X?}",
                oid, critical, value
            ),
        }
    }
}

impl Serialize for Extension {
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
        let oid: OID = seq.next_element()?.unwrap_or(0);
        let critical: bool = seq.next_element()?.unwrap_or(true);
        //let value: Vec<u8> = seq.next_element()?.unwrap_or_else(|| vec![0x0]);

        let ext = match oid {
            OID_KEYUSAGE => {
                let val: Option<KeyUsage> = seq.next_element()?;
                let keyusage_val = val.ok_or(de::Error::invalid_value(
                    de::Unexpected::Option,
                    &self,
                ))?;
                Extension::KeyUsage(keyusage_val)
            }
            _ => {
                let value: Vec<u8> = seq.next_element()?.unwrap_or_else(|| vec![0x0]);
                Extension::Unknown {
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
