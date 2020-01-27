use ed25519_dalek::SignatureError;
use serde_cbor::error::Error as SerdeError;

#[cfg(feature = "std")]
use std::io::Error as IoError;
use std::time::SystemTimeError;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub enum ValidationErrorCode {
    SignatureError,
    ValidityError { not_before: u64, not_after: u64 },
    TimeError,
    Untrusted,
}

#[derive(Debug)]
pub struct Error {
    pub(crate) code: ErrorCode,
}

#[derive(Debug)]
pub enum ErrorCode {
    Serialization(SerdeError),
    Signature(SignatureError),
    ExtensionValueError,
    ValidationError(ValidationErrorCode),
    #[cfg(feature = "std")]
    IO(IoError),
}

#[cfg(feature = "std")]
impl From<SystemTimeError> for Error {
    fn from(_err: SystemTimeError) -> Error {
        Error {
            code: ErrorCode::ValidationError(ValidationErrorCode::TimeError),
        }
    }
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
        Error {
            code: ErrorCode::Signature(err),
        }
    }
}

#[cfg(feature = "std")]
impl From<IoError> for Error {
    fn from(err: IoError) -> Error {
        Error {
            code: ErrorCode::IO(err),
        }
    }
}
