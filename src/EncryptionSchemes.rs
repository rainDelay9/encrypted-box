use openssl::symm::Cipher;

pub enum EncryptionSchemesE {
    Aes128Cbc = 1,
    Aes128Ofb = 2,
    Aes256Cbc = 3,
    Aes256Ecb = 4,
}

pub struct EncryptionSchemes;

impl EncryptionSchemes {
    pub fn fromEnum(e: EncryptionSchemesE) -> Cipher {
        match e {
            EncryptionSchemesE::Aes128Ofb => Cipher::aes_128_ofb(),
            EncryptionSchemesE::Aes128Cbc => Cipher::aes_128_cbc(),
            EncryptionSchemesE::Aes256Cbc => Cipher::aes_256_cbc(),
            EncryptionSchemesE::Aes256Ecb => Cipher::aes_256_ecb(),
            _ => panic!("Encryption scheme unsupported!"),
        }
    }
}
