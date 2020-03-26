use openssl::symm::{decrypt, encrypt, Cipher};

pub type EncryptionError = crate::crypto::utils::errors::EncryptionError;
pub type DecryptionError = crate::crypto::utils::errors::DecryptionError;

const IV16: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
const IV32: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

pub struct SymmetricCipher {
    cipher: Cipher,
}

impl SymmetricCipher {
    pub fn new(cipher: Cipher) -> SymmetricCipher {
        SymmetricCipher { cipher }
    }

    fn get_iv(&self) -> Option<&[u8]> {
        match self.cipher.iv_len() {
            Some(16) => Some(&IV16[..]),
            Some(32) => Some(&IV32[..]),
            _ => None,
        }
    }

    pub fn encrypt(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let expected_key_length = self.cipher.key_len();
        let actual_key_length = key.len();
        if expected_key_length != actual_key_length {
            return Result::Err(EncryptionError::new(String::from(format!(
                "key length incompatible. expected {} received {}",
                expected_key_length, actual_key_length
            ))));
        }
        let iv = self.get_iv();
        let enc = encrypt(self.cipher, key, iv, &msg[..]);
        match enc {
            Ok(encryption) => Result::Ok(encryption),
            Err(_) => Result::Err(EncryptionError::new(String::from("Unable to encrypt"))),
        }
    }

    pub fn decrypt(&self, key: &[u8], ctext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let expected_key_length = self.cipher.key_len();
        let actual_key_length = key.len();
        if expected_key_length != actual_key_length {
            return Result::Err(DecryptionError::new(String::from(format!(
                "key length incompatible. expected {} received {}",
                expected_key_length, actual_key_length
            ))));
        }
        let iv = self.get_iv();
        let dec = decrypt(self.cipher, key, iv, &ctext[..]);
        match dec {
            Ok(decryption) => Result::Ok(decryption),
            Err(_) => Result::Err(DecryptionError::new(String::from("Unable to encrypt"))),
        }
    }
}