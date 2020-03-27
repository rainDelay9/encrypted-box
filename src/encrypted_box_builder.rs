use crate::encrypted_box::EncryptedBox;
use crate::kdf;
use crate::openssl_aes::defs as aes_defs;
use crate::openssl_aes::util as aes_util;
use openssl::symm::Cipher;

pub struct EncryptedBoxBuilder {
    cipher: Cipher,
    fields: Vec<String>,
    key: Vec<u8>,
}

impl EncryptedBoxBuilder {
    pub fn new() -> EncryptedBoxBuilder {
        EncryptedBoxBuilder {
            cipher: Cipher::aes_128_cbc(),
            fields: Vec::new(),
            key: Vec::new(),
        }
    }

    pub fn add_field(&mut self, arg: String) -> &mut EncryptedBoxBuilder {
        self.fields.push(arg);
        self
    }

    pub fn set_password(&mut self, password: String) -> &mut EncryptedBoxBuilder {
        self.key = kdf::derive_key_from_password(&password);
        self
    }

    pub fn set_cipher(&mut self, e: aes_defs::OpenSslVariants) -> &mut EncryptedBoxBuilder {
        self.cipher = aes_util::cipher_from_enum(e);
        self
    }

    pub fn build(&self) -> EncryptedBox {
        let fields_str = self
            .fields
            .iter()
            .fold(String::new(), |res, field| res + field);
        EncryptedBox::new(fields_str, self.key.clone(), self.cipher)
    }
}
