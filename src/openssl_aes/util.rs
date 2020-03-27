pub use crate::openssl_aes::defs;
pub use openssl::symm::Cipher;

pub fn cipher_from_enum(e: defs::OpenSslVariants) -> Cipher {
    match e {
        defs::OpenSslVariants::Aes128Ofb => Cipher::aes_128_ofb(),
        defs::OpenSslVariants::Aes128Cbc => Cipher::aes_128_cbc(),
        defs::OpenSslVariants::Aes256Cbc => Cipher::aes_256_cbc(),
        defs::OpenSslVariants::Aes256Ecb => Cipher::aes_256_ecb(),
    }
}
