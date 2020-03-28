use openssl::symm::Cipher;

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
    Aes128Gcm,
    Aes128Ccm,
    Aes128Ofb,
    //AES192
    Aes192Ecb,
    Aes192Cbc,
    Aes192Ctr,
    Aes192Cfb1,
    Aes192Cfb128,
    Aes192Cfb8,
    Aes192Gcm,
    Aes192Ccm,
    Aes192Ofb,
    //AES256
    Aes256Ecb,
    Aes256Cbc,
    Aes256Xts,
    Aes256Ctr,
    Aes256Cfb1,
    Aes256Cfb128,
    Aes256Cfb8,
    Aes256Gcm,
    Aes256Ccm,
    Aes256Ofb,
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
        OpenSslVariants::Aes128Gcm => Cipher::aes_128_gcm(),
        OpenSslVariants::Aes128Ccm => Cipher::aes_128_ccm(),
        OpenSslVariants::Aes128Ofb => Cipher::aes_128_ofb(),
        //AES192
        OpenSslVariants::Aes192Ecb => Cipher::aes_192_ecb(),
        OpenSslVariants::Aes192Cbc => Cipher::aes_192_cbc(),
        OpenSslVariants::Aes192Ctr => Cipher::aes_192_ctr(),
        OpenSslVariants::Aes192Cfb1 => Cipher::aes_192_cfb1(),
        OpenSslVariants::Aes192Cfb128 => Cipher::aes_192_cfb128(),
        OpenSslVariants::Aes192Cfb8 => Cipher::aes_192_cfb8(),
        OpenSslVariants::Aes192Gcm => Cipher::aes_192_gcm(),
        OpenSslVariants::Aes192Ccm => Cipher::aes_192_ccm(),
        OpenSslVariants::Aes192Ofb => Cipher::aes_192_ofb(),
        //AES256
        OpenSslVariants::Aes256Ecb => Cipher::aes_256_ecb(),
        OpenSslVariants::Aes256Cbc => Cipher::aes_256_cbc(),
        OpenSslVariants::Aes256Xts => Cipher::aes_256_xts(),
        OpenSslVariants::Aes256Ctr => Cipher::aes_256_ctr(),
        OpenSslVariants::Aes256Cfb1 => Cipher::aes_256_cfb1(),
        OpenSslVariants::Aes256Cfb128 => Cipher::aes_256_cfb128(),
        OpenSslVariants::Aes256Cfb8 => Cipher::aes_256_cfb8(),
        OpenSslVariants::Aes256Gcm => Cipher::aes_256_gcm(),
        OpenSslVariants::Aes256Ccm => Cipher::aes_256_ccm(),
        OpenSslVariants::Aes256Ofb => Cipher::aes_256_ofb(),
    }
}
