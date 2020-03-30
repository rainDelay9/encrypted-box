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

#[cfg(test)]
mod tests {

    use super::EncryptedBox;
    use crate::encryption_scheme::EncryptionScheme;
    use crate::kdf;
    use crate::openssl_aes::{defs::OpenSslVariants as aes_variant, wrapper as aes};

    const FIELDS: &[u8; 16] = b"Some Crypto Text";
    const KEY: &'static [u8; 16] =
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    const PASSWORD: &'static str = "password";

    #[test]
    fn test_encrypt_with_vector() -> Result<(), aes::Error> {
        let scheme = aes::OpensslAesWrapper::new(&aes_variant::Aes128Cbc);

        let eb = EncryptedBox::new(FIELDS[..].to_vec(), KEY.to_vec(), scheme);
        let enc = eb.encrypt()?;

        // note: we use constant IVs tailored for this test case.
        // If IVs change then so should this test (since it will fail).
        assert_eq!(
            b"\xB4\xB9\xE7\x30\xD6\xD6\xF7\xDE\x77\x3F\x1C\xFF\xB3\x3E\x44\x5A\x91\xD7\x27\x62\x87\x4D\
              \xFB\x3C\x5E\xC4\x59\x72\x4A\xF4\x7C\xA1",
            &enc[..]);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), aes::Error> {
        let scheme = aes::OpensslAesWrapper::new(&aes_variant::Aes128Cbc);

        let pass = String::from(PASSWORD);
        let key = kdf::derive_key_from_password(&pass, scheme.get_key_length());

        let eb = EncryptedBox::new(FIELDS[..].to_vec(), key, scheme);
        let enc = eb.encrypt()?;
        let dec_eb: EncryptedBox<aes::OpensslAesWrapper> =
            EncryptedBox::decrypt(pass, &enc[..], aes_variant::Aes128Cbc)?;

        assert_eq!(dec_eb.fields[..], FIELDS[..]);
        Ok(())
    }
}
