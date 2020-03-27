use crate::kdf;
use crate::openssl_aes::wrapper as aes;

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

    pub fn encrypt(&self) -> std::vec::Vec<u8> {
        self.scheme
            .encrypt(&self.key[..], &self.fields[..])
            .expect("encryption failed!")
    }

    pub fn decrypt(
        password: String,
        ciphertext: &[u8],
        aes_enum: &aes::defs::OpenSslVariants,
    ) -> EncryptedBox {
        let scheme = aes::OpensslAesWrapper::new(aes_enum);
        let key = kdf::derive_key_from_password(&password, scheme.get_key_length());
        let fields = scheme
            .decrypt(&key, ciphertext)
            .expect("decryption failed!");
        EncryptedBox::new(fields, key, scheme)
    }
}
