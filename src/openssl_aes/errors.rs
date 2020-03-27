use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct OpensslError {
    error: String,
}
impl fmt::Display for OpensslError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OpensslError error: {}", self.error)
    }
}

impl OpensslError {
    pub fn new(error: String) -> OpensslError {
        OpensslError { error }
    }
}

impl Error for OpensslError {}
impl std::convert::From<openssl::error::ErrorStack> for OpensslError {
    fn from(es: openssl::error::ErrorStack) -> OpensslError {
        OpensslError::new(es.to_string())
    }
}
