use std::io::Error as IoError;
//use std::option::NoneError;
use std::num::ParseIntError;
use chrono::format::ParseError;
use smolcert::errors::Error as SmolcertError;

#[derive(Debug)]
pub struct Error {
  pub(crate) code: ErrorCode,
}

#[derive(Debug)]
pub enum ErrorCode {
  IO(IoError),
  Generic(String),
  //NoneError(NoneError),
  ParseInt(ParseIntError),
  TimeParse(ParseError),
  CertError(SmolcertError),
}

impl Error {
  pub fn new(msg: String) -> Self {
    Error{
      code: ErrorCode::Generic(msg)
    }
  }
}

impl From<SmolcertError> for Error {
  fn from(err: SmolcertError) -> Self {
    Error{
      code: ErrorCode::CertError(err)
    }
  }
}

impl From<ParseError> for Error {
  fn from(err: ParseError) -> Self {
    Error{
      code: ErrorCode::TimeParse(err)
    }
  }
}

impl From<ParseIntError> for Error {
  fn from(err: ParseIntError) -> Self {
    Error{
      code: ErrorCode::ParseInt(err)
    }
  }
}

/*impl From<NoneError> for Error {
  fn from(err: NoneError) -> Self {
    Error{
      code: ErrorCode::NoneError(err)
    }
  }
}*/

impl From<IoError> for Error {
  fn from(err: IoError) -> Error {
    Error{
      code: ErrorCode::IO(err)
    }
  }
}