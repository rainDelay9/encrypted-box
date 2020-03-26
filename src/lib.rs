mod EncryptedBox;
mod EncryptedBoxBuilder;
mod EncryptionSchemes;
mod kdf;

#[cfg(test)]
mod tests {
    use super::EncryptedBoxBuilder;
    use super::EncryptionSchemes;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
        EncryptedBoxBuilder::EncryptedBoxBuilder::new()
            .addField(String::from("hello"))
            .setCipher(EncryptionSchemes::EncryptionSchemesE::aes_128_ofb)
            .build();
    }
}
