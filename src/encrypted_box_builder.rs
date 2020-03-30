pub use crate::encrypted_box::EncryptedBox;
use crate::encryption_scheme::EncryptionScheme;
use crate::kdf;

pub struct EncryptedBoxBuilder<T> {
    cipher: T,
    fields: Vec<u8>,
    key: Vec<u8>,
}

impl<T> EncryptedBoxBuilder<T>
where
    T: EncryptionScheme + Clone,
{
    pub fn new(cipher: T) -> EncryptedBoxBuilder<T> {
        EncryptedBoxBuilder {
            cipher: cipher,
            fields: Vec::new(),
            key: Vec::new(),
        }
    }
    pub fn build(&mut self) -> EncryptedBox<T> {
        EncryptedBox::new(self.fields.clone(), self.key.clone(), self.cipher.clone())
    }
    pub fn add_field<'a, F>(&'a mut self, field: F) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString,
    {
        self.fields.extend(field.to_string().as_bytes());
        self
    }

    pub fn add_fields<'a, F>(&'a mut self, fields: &[F]) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString + std::fmt::Display,
    {
        for field in fields {
            self.add_field(field);
        }
        self
    }

    pub fn set_password<'a>(&'a mut self, password: String) -> &'a mut EncryptedBoxBuilder<T> {
        self.key = kdf::derive_key_from_password(&password, self.cipher.get_key_length());
        self
    }

    pub fn set_cipher<'a>(&'a mut self, cipher: &T) -> &'a mut EncryptedBoxBuilder<T> {
        self.cipher = cipher.clone();
        self
    }
}
