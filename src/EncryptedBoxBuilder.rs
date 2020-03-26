pub mod EncryptedBoxBuilder {

    use crate::kdf;
    use crate::EncryptedBox;
    use crate::EncryptionSchemes;
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

        pub fn addField(&mut self, arg: String) -> &mut EncryptedBoxBuilder {
            self.fields.push(arg);
            self
        }

        pub fn setPassword(&mut self, password: String) -> &mut EncryptedBoxBuilder {
            self.key = kdf::derive_key_from_password(&password);
            self
        }

        pub fn setCipher(
            &mut self,
            e: EncryptionSchemes::EncryptionSchemesE,
        ) -> &mut EncryptedBoxBuilder {
            self.cipher = EncryptionSchemes::EncryptionSchemes::fromEnum(e);
            self
        }

        pub fn build(&self) -> EncryptedBox::EncryptedBox {
            EncryptedBox::EncryptedBox {}
        }
    }
}
