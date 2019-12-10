use ed25519_dalek::{SignatureError};
use serde_cbor::error::Error as SerdeError;

#[derive(Debug)]
pub struct Error {
  code: ErrorCode,
}

#[derive(Debug)]
pub enum ErrorCode {
  Serialization(SerdeError),
  Signature(SignatureError),
}

impl From<SerdeError> for Error {
  fn from(err: SerdeError) -> Error {
    Error {
      code: ErrorCode::Serialization(err),
    }
  }
}

impl From<SignatureError> for Error {
  fn from(err: SignatureError) -> Error {
    Error{
      code: ErrorCode::Signature(err),
    }
  }
}