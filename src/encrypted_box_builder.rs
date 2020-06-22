pub use crate::encrypted_box::EncryptedBox;
pub use crate::encryption_scheme::EncryptionScheme;
use crate::kdf;
use exitfailure::ExitFailure;
use std::fmt;

/// This is a builder for an encrypted box object.
/// It is modeled after
/// https://doc.rust-lang.org/1.0.0/style/ownership/builders.html
/// as a non-consuming builder.
pub struct EncryptedBoxBuilder<T> {
    cipher: T,
    fields: Vec<u8>,
    key: Vec<u8>,
    password: String,
}

/// This is an implementation for an encrypted box builder
/// with a cipher that conforms to both Clone and EncryptionScheme
/// (see encryption_scheme.rs for more information)
impl<T> EncryptedBoxBuilder<T>
where
    T: EncryptionScheme + Clone,
{
    /// create a new builder with a given cipher
    pub fn new(cipher: T) -> EncryptedBoxBuilder<T> {
        EncryptedBoxBuilder {
            cipher: cipher,
            fields: Vec::new(),
            key: Vec::new(),
            password: String::from(""),
        }
    }

    /// generate a new EncryptedBox
    pub fn build(&mut self) -> Result<EncryptedBox<T>, ExitFailure> {
        if self.key.len() == 0 {
            return Err(ExitFailure::from(BuildError::new(
                "cannot build an encrypted box with no key",
            )));
        }
        Ok(EncryptedBox::new(
            self.fields.clone(),
            self.key.clone(),
            self.cipher.clone(),
        ))
    }

    /// add a field to the encryption data
    pub fn add_field<'a, F>(&'a mut self, field: F) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString,
    {
        self.fields.extend(field.to_string().as_bytes());
        self
    }

    /// add multiple fields at once
    pub fn add_fields<'a, F>(&'a mut self, fields: &[F]) -> &'a mut EncryptedBoxBuilder<T>
    where
        F: ToString + std::fmt::Display,
    {
        for field in fields {
            self.add_field(field);
        }
        self
    }

    /// set a password (of which a key will be derived)
    pub fn set_password<'a>(&'a mut self, password: String) -> &'a mut EncryptedBoxBuilder<T> {
        self.password = password;
        self.set_key(self.password.clone());
        self
    }

    fn set_key(&mut self, password: String) {
        self.key = kdf::derive_key_from_password(&password, self.cipher.get_key_length());
    }

    /// set a cipher to some other cipher
    /// this is handy if you are looking for a single builder with set fields
    /// to be encrypted by many ciphers
    pub fn set_cipher<'a>(&'a mut self, cipher: &T) -> &'a mut EncryptedBoxBuilder<T> {
        self.cipher = cipher.clone();
        // we need to reset the key for the new cipher
        self.set_key(self.password.clone());
        self
    }
}

#[derive(Debug)]
struct BuildError {
    cause: String,
}

impl BuildError {
    pub fn new(cause: &str) -> BuildError {
        BuildError {
            cause: cause.to_string(),
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "build failed! {}", self.cause)
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssl_aes::{defs::OpenSslVariants as variants, wrapper as aes};

    // note: this text is long on purpose, as some modes of AES show differences only
    // with large enough plaintexts
    const LONG_TEXT : &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec posuere cursus faucibus. Maecenas congue lectus vitae orci elementum pretium. Vestibulum ornare consectetur tellus, eget malesuada quam dapibus quis. Sed arcu quam, molestie sed lobortis vitae, iaculis at sem. Etiam ligula urna, viverra ut erat sed, luctus laoreet velit. Integer tempor sed mauris efficitur laoreet. Etiam ipsum est, varius in est id, blandit ultricies ex. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Fusce vulputate velit quis urna porta, volutpat maximus ex ornare. Sed ut turpis quis tortor posuere interdum. Morbi nec augue sit amet odio efficitur.";

    #[test]
    fn add_int_field_test() {
        let field = 42;
        let mut ebb = EncryptedBoxBuilder::new(aes::OpensslAesWrapper::new(&variants::Aes128Cbc));
        let ebb = ebb.add_field(&field);
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(field.to_string().as_bytes());
        assert_eq!(ebb.fields, vec);
    }

    fn add_fields_test<T>(fields: Vec<T>)
    where
        T: ToString + std::fmt::Display,
    {
        let mut ebb = EncryptedBoxBuilder::new(aes::OpensslAesWrapper::new(&variants::Aes128Cbc));
        let ebb = ebb.add_fields(&fields);
        let mut vec: Vec<u8> = Vec::new();
        for field in fields.iter() {
            vec.extend(field.to_string().as_bytes());
        }
        assert_eq!(ebb.fields, vec);
    }

    #[test]
    fn add_int_fields_test() {
        let fields = [42, 22, 15, 19];
        add_fields_test(fields.to_vec());
    }

    #[test]
    fn add_str_fields_test() {
        let fields = ["aaa", "bbbb", "cccc", "dddd"];
        add_fields_test(fields.to_vec());
    }

    #[test]
    fn set_long_password() -> Result<(), ExitFailure> {
        let mut ebb = EncryptedBoxBuilder::new(aes::OpensslAesWrapper::new(&variants::Aes128Cbc));
        ebb.set_password(String::from(LONG_TEXT));
        ebb.build()?;
        Ok(())
    }

    #[test]
    fn set_password_forall_aes_variants() {
        let password = String::from("password");
        for variant in variants::iterator() {
            let scheme = aes::OpensslAesWrapper::new(variant);
            let mut ebb = EncryptedBoxBuilder::new(scheme);
            let ebb = ebb.set_password(password.clone());
            let key: Vec<u8> = kdf::derive_key_from_password(&password, scheme.get_key_length());
            assert_eq!(ebb.key, key);
        }
    }

    #[test]
    fn build_fails_when_no_password_is_set() -> Result<(), ExitFailure> {
        let scheme = aes::OpensslAesWrapper::new(&variants::Aes192Cbc);

        // initialize builder & encrypted-box
        let mut ebb = EncryptedBoxBuilder::new(scheme);
        let eb = ebb.add_field("field").build();
        match eb {
            Ok(_) => assert!(false),
            _ => assert!(true),
        }
        Ok(())
    }

    #[test]
    fn set_cipher_forall_aes_variants_differect_encryption() -> Result<(), ExitFailure> {
        for variant1 in variants::iterator() {
            // create encrypted box builder with first variant
            let scheme1 = aes::OpensslAesWrapper::new(variant1);
            let mut ebb = EncryptedBoxBuilder::new(scheme1);
            let eb1 = ebb
                .set_password(String::from("password"))
                .add_field(LONG_TEXT)
                .build()?;
            let ctext1 = eb1.encrypt()?;
            for variant2 in variants::iterator() {
                if variant1 == variant2 {
                    continue;
                }
                // change cipher to different cipher
                let scheme2 = aes::OpensslAesWrapper::new(variant2);
                let ebb = ebb.set_cipher(&scheme2);
                let eb2 = ebb.build()?;
                let ctext2 = eb2.encrypt()?;

                //test that encryptions differ
                assert_ne!(ctext1, ctext2);
            }
        }
        Ok(())
    }

    #[test]
    fn key_reset_after_cipher_changed() -> Result<(), ExitFailure> {
        // create encrypted box builder with first variant
        let init_scheme = aes::OpensslAesWrapper::new(&variants::Aes128Cbc);
        let mut ebb = EncryptedBoxBuilder::new(init_scheme);
        let ebb = ebb
            .set_password(String::from("password"))
            .add_field(LONG_TEXT);
        for variant in variants::iterator() {
            let change_scheme = aes::OpensslAesWrapper::new(variant);
            let key_len = change_scheme.get_key_length();
            let ebb = ebb.set_cipher(&change_scheme);
            //test that key length is as supposed to be
            assert_eq!(ebb.key.len(), key_len);
        }
        Ok(())
    }
}
