use super::*;

#[cfg(feature = "std")]
use std::fmt;

use serde::ser::{Serialize, Serializer};
use serde::de;

pub type OID = u64;

pub const OID_KEYUSAGE: OID = 0x10;

#[derive(Debug, Clone, Copy)]
//#[serde(untagged)]
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

impl KeyUsage {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(KeyUsage::ClientIdentification),
            0x02 => Ok(KeyUsage::ServerIdentification),
            0x03 => Ok(KeyUsage::SignCertificate),
            _ => Err(Error{
                code: ErrorCode::ExtensionValueError,
            })
        }
    }

    pub fn from_slice(val: &[u8]) -> Result<Self> {
        if val.len() != 1 {
            return Err(Error{
                code: ErrorCode::ExtensionValueError,
            });
        }
        KeyUsage::from_u8(val[0])
    }
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
            Extension::KeyUsage(v) => write!(f, "Key usage (critical extension): {}", v),
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
        let value_val = serde_cbor::Value::Bytes(self.value());
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
        let cbor_value: serde_cbor::Value = seq.next_element()?.unwrap_or_else(|| serde_cbor::Value::Bytes(vec![0x0]));

        let value = match cbor_value {
            serde_cbor::Value::Bytes(v) => v,
            _ => return Err(de::Error::invalid_value(
                de::Unexpected::Other("Expected a byte string representing the Extension value"),
                &self,
            )),
        };

        let ext = match oid {
            OID_KEYUSAGE => {
                // FIXME, we need proper error handling here...
                let key_usage = KeyUsage::from_slice(&value).unwrap();
                Extension::KeyUsage(key_usage)
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

impl<'de> de::Deserialize<'de> for Extension {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ExtensionVisitor)
    }
}
