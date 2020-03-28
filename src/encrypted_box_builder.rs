use crate::encrypted_box::EncryptedBox;
use crate::kdf;
use crate::openssl_aes::{defs as aes_defs, wrapper as aes};

#[allow(dead_code)]
pub struct EncryptedBoxBuilder {
    cipher: aes::OpensslAesWrapper,
    fields: Vec<u8>,
    key: Vec<u8>,
}

impl EncryptedBoxBuilder {
    pub fn new() -> EncryptedBoxBuilder {
        EncryptedBoxBuilder {
            cipher: aes::OpensslAesWrapper::new(&aes::defs::OpenSslVariants::Aes128Cbc),
            fields: Vec::new(),
            key: Vec::new(),
        }
    }

    pub fn add_field<'a, T>(&'a mut self, arg: T) -> &'a mut EncryptedBoxBuilder
    where
        T: ToString,
    {
        self.fields.extend(arg.to_string().as_bytes());
        self
    }

    pub fn set_password<'a>(&'a mut self, password: String) -> &'a mut EncryptedBoxBuilder {
        self.key = kdf::derive_key_from_password(&password, self.cipher.get_key_length());
        self
    }

    pub fn set_cipher<'a>(
        &'a mut self,
        e: &aes_defs::OpenSslVariants,
    ) -> &'a mut EncryptedBoxBuilder {
        self.cipher = aes::OpensslAesWrapper::new(e);
        self
    }

    pub fn build(&mut self) -> EncryptedBox {
        EncryptedBox::new(self.fields.clone(), self.key.clone(), self.cipher)
    }
}
