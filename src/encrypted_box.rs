use crate::openssl_aes::wrapper as aes;

pub struct EncryptedBox {
    fields: String,
    key: Vec<u8>,
    cipher: aes::OpensslAesWrapper,
}

impl EncryptedBox {
    pub fn new(fields: String, key: Vec<u8>, cipher: aes::OpensslAesWrapper) -> EncryptedBox {
        EncryptedBox {
            fields,
            key,
            cipher,
        }
    }
}
