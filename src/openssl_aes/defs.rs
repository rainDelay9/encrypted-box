use openssl::symm::Cipher;
use std::slice::Iter;

#[allow(dead_code)]
pub enum OpenSslVariants {
    //AES128
    Aes128Ecb,
    Aes128Cbc,
    Aes128Xts,
    Aes128Ctr,
    Aes128Cfb1,
    Aes128Cfb128,
    Aes128Cfb8,
    Aes128Ofb,
    //AES192
    Aes192Ecb,
    Aes192Cbc,
    Aes192Ctr,
    Aes192Cfb1,
    Aes192Cfb128,
    Aes192Cfb8,
    Aes192Ofb,
    //AES256
    Aes256Ecb,
    Aes256Cbc,
    Aes256Xts,
    Aes256Ctr,
    Aes256Cfb1,
    Aes256Cfb128,
    Aes256Cfb8,
    Aes256Ofb,
}

impl OpenSslVariants {
    pub fn iterator() -> Iter<'static, OpenSslVariants> {
        static VARIANTS: [OpenSslVariants; 23] = [
            //AES128
            OpenSslVariants::Aes128Ecb,
            OpenSslVariants::Aes128Cbc,
            OpenSslVariants::Aes128Xts,
            OpenSslVariants::Aes128Ctr,
            OpenSslVariants::Aes128Cfb1,
            OpenSslVariants::Aes128Cfb128,
            OpenSslVariants::Aes128Cfb8,
            OpenSslVariants::Aes128Ofb,
            //AES192
            OpenSslVariants::Aes192Ecb,
            OpenSslVariants::Aes192Cbc,
            OpenSslVariants::Aes192Ctr,
            OpenSslVariants::Aes192Cfb1,
            OpenSslVariants::Aes192Cfb128,
            OpenSslVariants::Aes192Cfb8,
            OpenSslVariants::Aes192Ofb,
            //AES256
            OpenSslVariants::Aes256Ecb,
            OpenSslVariants::Aes256Cbc,
            OpenSslVariants::Aes256Xts,
            OpenSslVariants::Aes256Ctr,
            OpenSslVariants::Aes256Cfb1,
            OpenSslVariants::Aes256Cfb128,
            OpenSslVariants::Aes256Cfb8,
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
        OpenSslVariants::Aes128Xts => Cipher::aes_128_xts(),
        OpenSslVariants::Aes128Ctr => Cipher::aes_128_ctr(),
        OpenSslVariants::Aes128Cfb1 => Cipher::aes_128_cfb1(),
        OpenSslVariants::Aes128Cfb128 => Cipher::aes_128_cfb128(),
        OpenSslVariants::Aes128Cfb8 => Cipher::aes_128_cfb8(),
        OpenSslVariants::Aes128Ofb => Cipher::aes_128_ofb(),
        //AES192
        OpenSslVariants::Aes192Ecb => Cipher::aes_192_ecb(),
        OpenSslVariants::Aes192Cbc => Cipher::aes_192_cbc(),
        OpenSslVariants::Aes192Ctr => Cipher::aes_192_ctr(),
        OpenSslVariants::Aes192Cfb1 => Cipher::aes_192_cfb1(),
        OpenSslVariants::Aes192Cfb128 => Cipher::aes_192_cfb128(),
        OpenSslVariants::Aes192Cfb8 => Cipher::aes_192_cfb8(),
        OpenSslVariants::Aes192Ofb => Cipher::aes_192_ofb(),
        //AES256
        OpenSslVariants::Aes256Ecb => Cipher::aes_256_ecb(),
        OpenSslVariants::Aes256Cbc => Cipher::aes_256_cbc(),
        OpenSslVariants::Aes256Xts => Cipher::aes_256_xts(),
        OpenSslVariants::Aes256Ctr => Cipher::aes_256_ctr(),
        OpenSslVariants::Aes256Cfb1 => Cipher::aes_256_cfb1(),
        OpenSslVariants::Aes256Cfb128 => Cipher::aes_256_cfb128(),
        OpenSslVariants::Aes256Cfb8 => Cipher::aes_256_cfb8(),
        OpenSslVariants::Aes256Ofb => Cipher::aes_256_ofb(),
    }
}
