pub use crate::encryption_scheme::EncryptionScheme;
pub use crate::openssl_aes::{
    defs, defs::OpenSslVariants, errors::Error, errors::ErrorKind, errors::Result,
};
use openssl::symm::{decrypt, encrypt, Cipher};

const _IV12: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";
const _IV16: &'static [u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

#[derive(Copy, Clone)]
pub struct OpensslAesWrapper {
    cipher: Cipher,
}

impl OpensslAesWrapper {
    pub fn get_iv_length(&self) -> Option<usize> {
        self.cipher.iv_len()
    }

    // currently we only support 12-byte or 16-byte IVs
    fn get_iv(&self) -> Option<&[u8]> {
        match self.get_iv_length() {
            Some(12) => Some(&_IV12[..]),
            Some(16) => Some(&_IV16[..]),
            _ => None,
        }
    }

    /// check that key length matches the required key length
    fn check_key_len(&self, key_len: usize) -> Result<()> {
        let expected_key_length = self.get_key_length();
        if expected_key_length != key_len {
            return Result::Err(Error::keylen(expected_key_length, key_len));
        };
        Ok(())
    }
}

/// See encryption_scheme.rs
impl EncryptionScheme for OpensslAesWrapper {
    /// error type returned (openssl_aes::errors::Error)
    type Error = Error;

    /// variant type is OpenSslVariants
    type Variant = OpenSslVariants;

    fn new(v: &OpenSslVariants) -> OpensslAesWrapper {
        OpensslAesWrapper {
            cipher: defs::openssl_enum_to_cipher(v),
        }
    }

    fn get_key_length(&self) -> usize {
        self.cipher.key_len()
    }
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        self.check_key_len(key.len())?;
        let iv = self.get_iv();
        let enc = encrypt(self.cipher, key, iv, &msg[..]).map_err(|e| Error::encryption(e))?;
        Ok(enc)
    }
    fn decrypt(&self, key: &[u8], ctext: &[u8]) -> Result<Vec<u8>> {
        self.check_key_len(key.len())?;
        let iv = self.get_iv();
        let dec = decrypt(self.cipher, key, iv, &ctext[..]).map_err(|e| Error::decryption(e))?;
        Ok(dec)
    }
}

#[cfg(test)]
mod tests {
    use super::OpensslAesWrapper;
    use crate::encryption_scheme::EncryptionScheme;
    use crate::kdf;
    use crate::openssl_aes::{defs::OpenSslVariants, errors::Result};

    const MSG: [u8; 17] = [
        84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 109, 101, 115, 115, 97, 103, 101,
    ];
    const PASSWORD: &'static str = "password";
    #[test]
    fn encrypt_decrypt_all_schemes() -> Result<()> {
        for variant in OpenSslVariants::iterator() {
            let wrapper = OpensslAesWrapper::new(&variant);
            let key =
                kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length());
            let enc = wrapper.encrypt(&key[..], &MSG)?;
            let dec = wrapper.decrypt(&key[..], &enc[..])?;
            assert_eq!(dec, MSG);
        }
        Ok(())
    }

    // when running the following test one must notice that in some of the schemes the
    // decryption with a different key panics, and in some simply returns a value
    // somewhat inconsistent behavior, I'm assuming from there being a difference between the schemes
    #[test]
    fn decrypt_with_different_key_should_mismatch() -> Result<()> {
        let wrapper = OpensslAesWrapper::new(&OpenSslVariants::Aes128Ctr);
        let mut key =
            kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length());
        let enc = wrapper.encrypt(&key[..], &MSG)?;
        key.pop();
        key.push(10);
        let dec = wrapper.decrypt(&key[..], &enc[..])?;
        assert_ne!(&MSG[..], &dec[..]);
        Ok(())
    }

    #[test]
    fn error_on_encrypt_key_length_too_short() {
        let wrapper = OpensslAesWrapper::new(&OpenSslVariants::Aes128Ctr);
        let key =
            kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length() - 1);
        let enc = wrapper.encrypt(&key[..], &MSG);
        match enc {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn error_on_encrypt_key_length_too_long() {
        let wrapper = OpensslAesWrapper::new(&OpenSslVariants::Aes128Ctr);
        let key =
            kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length() + 1);
        let enc = wrapper.encrypt(&key[..], &MSG);
        match enc {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }
    #[test]
    fn error_on_decrypt_key_length_too_short() -> Result<()> {
        let wrapper = OpensslAesWrapper::new(&OpenSslVariants::Aes128Ctr);
        let key = kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length());
        let enc = wrapper.encrypt(&key[..], &MSG)?;
        let short_key_len = wrapper.get_key_length() - 1;
        let dec = wrapper.decrypt(&key[..short_key_len], &enc[..]);
        match dec {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
        Ok(())
    }

    #[test]
    fn error_on_decrypt_key_length_too_long() -> Result<()> {
        let wrapper = OpensslAesWrapper::new(&OpenSslVariants::Aes128Ctr);
        let mut key =
            kdf::derive_key_from_password(&String::from(PASSWORD), wrapper.get_key_length());
        let enc = wrapper.encrypt(&key[..], &MSG)?;
        key.push(10);
        let dec = wrapper.decrypt(&key[..], &enc[..]);
        match dec {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
        Ok(())
    }
}
