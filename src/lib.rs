pub mod encrypted_box;
pub mod encrypted_box_builder;
pub mod encryption_scheme;
pub mod kdf;
pub mod openssl_aes;

// #[cfg(test)]
// mod tests {
//     use super::encrypted_box::EncryptedBox;
//     use super::encrypted_box_builder::EncryptedBoxBuilder;
//     use super::openssl_aes::defs::OpenSslVariants;
//     #[test]
//     fn it_works() {
//         let variant = OpenSslVariants::Aes192Ctr;
//         let mut ebb = EncryptedBoxBuilder::new();
//         let data = "Lorem ipsum dolor sit amet";
//         let mut vec1: std::vec::Vec<u8> = Vec::new();
//         vec1.extend(data.to_string().as_bytes());
//         println!("{:?}", vec1);
//         let eb = ebb
//             .add_field(data)
//             .set_cipher(&variant)
//             .set_password(String::from("password"))
//             .build();
//         let res = eb.encrypt().expect("encryption failed");
//         let _eb2 = EncryptedBox::decrypt(String::from("password"), &res[..], &variant);
//     }
// }
