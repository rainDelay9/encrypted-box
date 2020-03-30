pub use crate::encrypted_box::EncryptedBox;
use crate::encryption_scheme::EncryptionScheme;
use crate::kdf;
use exitfailure::ExitFailure;
use std::fmt;

/// This is a builder for an encrypted box object.
/// It is modeled after
/// https://doc.rust-lang.org/1.0.0/style/ownership/builders.html
/// as a non-consuming builder.
pub struct EncryptedBoxBuilder<T> {
    cipher: T,
    fields: Vec<u8>,
    key: Vec<u8>,
}

/// This is an implementation for an encrypted box builder
/// with a cipher that conforms to both Clone and EncryptionScheme
/// (see encryption_scheme.rs for more information)
impl<T> EncryptedBoxBuilder<T>
where
    T: EncryptionScheme + Clone,
{
    /// create a new builder with a given cipher
    pub fn new(cipher: T) -> EncryptedBoxBuilder<T> {
        EncryptedBoxBuilder {
            cipher: cipher,
            fields: Vec::new(),
            key: Vec::new(),
        }
    }

    /// generate a new EncryptedBox
    pub fn build(&mut self) -> Result<EncryptedBox<T>, ExitFailure> {
        if self.key.len() == 0 {
            return Err(ExitFailure::from(BuildError::new(
                "cannot build an encrypted box with no key",
            )));
        }
        Ok(EncryptedBox::new(
            self.fields.clone(),
            self.key.clone(),
            self.cipher.clone(),
        ))
    }

    /// add a field to the encryption data
    pub fn add_field<'a, F>(&'a mut self, field: F) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString,
    {
        self.fields.extend(field.to_string().as_bytes());
        self
    }

    /// add multiple fields at once
    pub fn add_fields<'a, F>(&'a mut self, fields: &[F]) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString + std::fmt::Display,
    {
        for field in fields {
            self.add_field(field);
        }
        self
    }

    /// set a password (of which a key will be derived)
    pub fn set_password<'a>(&'a mut self, password: String) -> &'a mut EncryptedBoxBuilder<T> {
        self.key = kdf::derive_key_from_password(&password, self.cipher.get_key_length());
        self
    }

    /// set a cipher to some other cipher
    /// this is handy id you are looking for a single builder with set fields
    /// to be encrypted by many ciphers
    pub fn set_cipher<'a>(&'a mut self, cipher: &T) -> &'a mut EncryptedBoxBuilder<T> {
        self.cipher = cipher.clone();
        self
    }
}

#[derive(Debug)]
struct BuildError {
    cause: String,
}

impl BuildError {
    pub fn new(cause: &str) -> BuildError {
        BuildError {
            cause: cause.to_string(),
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "build failed! {}", self.cause)
    }
}

impl std::error::Error for BuildError {}
