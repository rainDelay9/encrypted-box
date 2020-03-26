use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct EncryptionError {
    error: String,
}
impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Encryption error: {}", self.error)
    }
}

impl EncryptionError {
    pub fn new(error: String) -> EncryptionError {
        EncryptionError { error }
    }
}

impl Error for EncryptionError {}

#[derive(Debug)]
pub struct DecryptionError {
    error: String,
}
impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decryption error: {}", self.error)
    }
}

impl DecryptionError {
    pub fn new(error: String) -> DecryptionError {
        DecryptionError { error }
    }
}

impl Error for DecryptionError {}
