use crate::encryption_scheme::EncryptionScheme;
use crate::kdf;

/// An implementation of an encrypted box
/// which holds the encryption of a few fields
pub struct EncryptedBox<T> {
    fields: Vec<u8>,
    key: Vec<u8>,
    scheme: T,
}

impl<T> EncryptedBox<T>
where
    T: EncryptionScheme + Clone,
{
    /// create a new encrypted box
    pub fn new(fields: Vec<u8>, key: Vec<u8>, scheme: T) -> EncryptedBox<T> {
        EncryptedBox {
            fields,
            key,
            scheme,
        }
    }

    /// encrypt content (fields)
    pub fn encrypt(&self) -> Result<Vec<u8>, T::Error> {
        self.scheme.encrypt(&self.key[..], &self.fields[..])
    }

    /// decrypt ciphertext into new encrypted box
    pub fn decrypt(
        password: String,
        ciphertext: &[u8],
        v: T::Variant,
    ) -> Result<EncryptedBox<T>, T::Error> {
        let scheme = T::new(&v);
        let key = kdf::derive_key_from_password(&password, scheme.get_key_length());
        let fields = scheme.decrypt(&key, ciphertext)?;
        Ok(EncryptedBox::new(fields, key, scheme))
    }
}
