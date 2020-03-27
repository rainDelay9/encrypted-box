use crate::openssl_aes::wrapper as aes;
use openssl::symm::Cipher;

pub struct EncryptedBox {
    fields: String,
    key: Vec<u8>,
    cipher: Cipher,
}

impl EncryptedBox {
    pub fn new(fields: String, key: Vec<u8>, cipher: Cipher) -> EncryptedBox {
        EncryptedBox {
            fields,
            key,
            cipher,
        }
    }
}
