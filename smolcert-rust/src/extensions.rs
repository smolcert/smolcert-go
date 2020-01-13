use super::*;

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