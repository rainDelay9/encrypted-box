use crate::encrypted_box::EncryptedBox;
use crate::kdf;
use crate::openssl_aes::defs as aes_defs;
use crate::openssl_aes::wrapper as aes;

#[allow(dead_code)]
pub struct EncryptedBoxBuilder {
    cipher: aes::OpensslAesWrapper,
    fields: Vec<u8>,
    key: Vec<u8>,
}

impl EncryptedBoxBuilder {
    pub fn new() -> EncryptedBoxBuilder {
        EncryptedBoxBuilder {
            cipher: aes::OpensslAesWrapper::new(aes::defs::OpenSslVariants::Aes128Cbc),
            fields: Vec::new(),
            key: Vec::new(),
        }
    }

    pub fn add_field<T>(mut self, arg: T) -> EncryptedBoxBuilder
    where
        T: ToString,
    {
        self.fields.extend(arg.to_string().as_bytes());
        self
    }

    pub fn set_password(mut self, password: String) -> EncryptedBoxBuilder {
        self.key = kdf::derive_key_from_password(&password);
        self
    }

    pub fn set_cipher(mut self, e: aes_defs::OpenSslVariants) -> EncryptedBoxBuilder {
        self.cipher = aes::OpensslAesWrapper::new(e);
        self
    }

    pub fn build(self) -> EncryptedBox {
        EncryptedBox::new(self.fields, self.key, self.cipher)
    }
}
