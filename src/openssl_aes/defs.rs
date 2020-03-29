use crate::openssl_aes::errors;
use openssl::symm::Cipher;
use std::slice::Iter;

#[allow(dead_code)]
pub enum OpenSslVariants {
    //AES128
    Aes128Ecb,
    Aes128Cbc,
    Aes128Ctr,
    Aes128Ofb,
    //AES192
    Aes192Ecb,
    Aes192Cbc,
    Aes192Ctr,
    Aes192Ofb,
    //AES256
    Aes256Ecb,
    Aes256Cbc,
    Aes256Ctr,
    Aes256Ofb,
}

impl OpenSslVariants {
    pub fn iterator() -> Iter<'static, OpenSslVariants> {
        static VARIANTS: [OpenSslVariants; 12] = [
            //AES128
            OpenSslVariants::Aes128Ecb,
            OpenSslVariants::Aes128Cbc,
            OpenSslVariants::Aes128Ctr,
            OpenSslVariants::Aes128Ofb,
            //AES192
            OpenSslVariants::Aes192Ecb,
            OpenSslVariants::Aes192Cbc,
            OpenSslVariants::Aes192Ctr,
            OpenSslVariants::Aes192Ofb,
            //AES256
            OpenSslVariants::Aes256Ecb,
            OpenSslVariants::Aes256Cbc,
            OpenSslVariants::Aes256Ctr,
            OpenSslVariants::Aes256Ofb,
        ];
        VARIANTS.iter()
    }
}

pub fn openssl_enum_to_cipher(e: &OpenSslVariants) -> Cipher {
    match e {
        //AES128
        OpenSslVariants::Aes128Ecb => Cipher::aes_128_ecb(),
        OpenSslVariants::Aes128Cbc => Cipher::aes_128_cbc(),
        OpenSslVariants::Aes128Ctr => Cipher::aes_128_ctr(),
        OpenSslVariants::Aes128Ofb => Cipher::aes_128_ofb(),
        //AES192
        OpenSslVariants::Aes192Ecb => Cipher::aes_192_ecb(),
        OpenSslVariants::Aes192Cbc => Cipher::aes_192_cbc(),
        OpenSslVariants::Aes192Ctr => Cipher::aes_192_ctr(),
        OpenSslVariants::Aes192Ofb => Cipher::aes_192_ofb(),
        //AES256
        OpenSslVariants::Aes256Ecb => Cipher::aes_256_ecb(),
        OpenSslVariants::Aes256Cbc => Cipher::aes_256_cbc(),
        OpenSslVariants::Aes256Ctr => Cipher::aes_256_ctr(),
        OpenSslVariants::Aes256Ofb => Cipher::aes_256_ofb(),
    }
}

pub fn openssl_index_to_enum<'a>(index: u32) -> Result<OpenSslVariants, errors::Error> {
    match index {
        //AES128
        0 => Ok(OpenSslVariants::Aes128Ecb),
        1 => Ok(OpenSslVariants::Aes128Cbc),
        2 => Ok(OpenSslVariants::Aes128Ctr),
        3 => Ok(OpenSslVariants::Aes128Ofb),
        //AES192
        4 => Ok(OpenSslVariants::Aes192Ecb),
        5 => Ok(OpenSslVariants::Aes192Cbc),
        6 => Ok(OpenSslVariants::Aes192Ctr),
        7 => Ok(OpenSslVariants::Aes192Ofb),
        //AES256
        8 => Ok(OpenSslVariants::Aes256Ecb),
        9 => Ok(OpenSslVariants::Aes256Cbc),
        10 => Ok(OpenSslVariants::Aes256Ctr),
        11 => Ok(OpenSslVariants::Aes256Ofb),
        _ => Err(errors::Error::unsupported(
            "The scheme index is unsupported!",
        )),
    }
}
