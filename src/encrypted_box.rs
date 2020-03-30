use crate::encryption_scheme::EncryptionScheme;
use crate::kdf;

pub struct EncryptedBox<T> {
    fields: Vec<u8>,
    key: Vec<u8>,
    scheme: T,
}

impl<T> EncryptedBox<T>
where
    T: EncryptionScheme + Clone,
{
    pub fn new(fields: Vec<u8>, key: Vec<u8>, scheme: T) -> EncryptedBox<T> {
        EncryptedBox {
            fields,
            key,
            scheme,
        }
    }

    pub fn encrypt(&self) -> Result<Vec<u8>, T::Error> {
        self.scheme.encrypt(&self.key[..], &self.fields[..])
    }

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
