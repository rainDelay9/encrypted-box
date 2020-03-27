mod encrypted_box;
mod encrypted_box_builder;
mod kdf;
mod openssl_aes;

#[cfg(test)]
mod tests {
    use super::encrypted_box::EncryptedBox;
    use super::encrypted_box_builder::EncryptedBoxBuilder;
    use super::openssl_aes::defs::OpenSslVariants;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
        let eb = EncryptedBoxBuilder::new()
            .add_field(42)
            .set_cipher(OpenSslVariants::Aes256Cbc)
            .set_password(String::from("password"))
            .build();
        let res = eb.encrypt();
        let _eb2 = EncryptedBox::decrypt(
            String::from("password"),
            &res[..],
            OpenSslVariants::Aes256Cbc,
        );
    }
}
