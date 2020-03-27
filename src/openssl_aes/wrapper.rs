pub use crate::openssl_aes::{defs, errors};
use openssl::symm::{decrypt, encrypt, Cipher};

const _IV16: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
const _IV32: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

pub struct OpensslAesWrapper {
    cipher: Cipher,
}

impl OpensslAesWrapper {
    pub fn new(e: &defs::OpenSslVariants) -> OpensslAesWrapper {
        match e {
            defs::OpenSslVariants::Aes128Ofb => OpensslAesWrapper {
                cipher: Cipher::aes_128_ofb(),
            },
            defs::OpenSslVariants::Aes128Cbc => OpensslAesWrapper {
                cipher: Cipher::aes_128_cbc(),
            },
            defs::OpenSslVariants::Aes256Cbc => OpensslAesWrapper {
                cipher: Cipher::aes_256_cbc(),
            },
            defs::OpenSslVariants::Aes256Ecb => OpensslAesWrapper {
                cipher: Cipher::aes_256_ecb(),
            },
        }
    }

    pub fn get_key_length(&self) -> usize {
        self.cipher.key_len()
    }
    pub fn encrypt(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, errors::OpensslError> {
        self.check_key_len(key.len())?;
        let iv = self.get_iv();
        let enc = encrypt(self.cipher, key, iv, &msg[..])?;
        Ok(enc)
    }
    pub fn decrypt(&self, key: &[u8], ctext: &[u8]) -> Result<Vec<u8>, errors::OpensslError> {
        self.check_key_len(key.len())?;
        let iv = self.get_iv();
        let dec = decrypt(self.cipher, key, iv, &ctext[..])?;
        Ok(dec)
    }

    // currently we only support 16-byte or 32-byte IVs
    fn get_iv(&self) -> Option<&[u8]> {
        match self.cipher.iv_len() {
            Some(16) => Some(&_IV16[..]),
            Some(32) => Some(&_IV32[..]),
            _ => None,
        }
    }

    fn check_key_len(&self, key_len: usize) -> Result<(), errors::OpensslError> {
        let expected_key_length = self.get_key_length();
        if expected_key_length != key_len {
            return Result::Err(errors::OpensslError::new(String::from(format!(
                "key length incompatible. expected {} received {}",
                expected_key_length, key_len
            ))));
        };
        Ok(())
    }
}
