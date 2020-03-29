use crate::kdf;
use crate::openssl_aes::{errors as aes_errors, wrapper as aes};

pub struct EncryptedBox {
    fields: Vec<u8>,
    key: Vec<u8>,
    scheme: aes::OpensslAesWrapper,
}

impl EncryptedBox {
    pub fn new(fields: Vec<u8>, key: Vec<u8>, scheme: aes::OpensslAesWrapper) -> EncryptedBox {
        EncryptedBox {
            fields,
            key,
            scheme,
        }
    }

    pub fn encrypt(&self) -> aes_errors::Result<Vec<u8>> {
        self.scheme.encrypt(&self.key[..], &self.fields[..])
    }

    pub fn decrypt(
        password: String,
        ciphertext: &[u8],
        aes_enum: &aes::defs::OpenSslVariants,
    ) -> aes_errors::Result<EncryptedBox> {
        let scheme = aes::OpensslAesWrapper::new(aes_enum);
        let key = kdf::derive_key_from_password(&password, scheme.get_key_length());
        let fields = scheme.decrypt(&key, ciphertext)?;
        Ok(EncryptedBox::new(fields, key, scheme))
    }
}
