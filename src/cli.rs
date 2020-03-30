use crate::encrypted_box_builder::EncryptedBoxBuilder;
use crate::encryption_scheme::EncryptionScheme;
use crate::openssl_aes::{defs as aes_defs, wrapper as aes};
use base64;
use exitfailure::ExitFailure;
use failure::ResultExt;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

pub fn cli() -> Result<(), ExitFailure> {
    let opt = Opt::from_args();

    // get password
    let password: String = get_password(opt.password, opt.path_to_password)
        .with_context(|_| format!("could not determine password!"))?;

    // get aes scheme
    let aes_enum = aes_defs::openssl_index_to_enum(opt.scheme)
        .with_context(|_| format!("unsupported scheme!"))?;
    let scheme = aes::OpensslAesWrapper::new(&aes_enum);

    // initialize builder & encrypted-box
    let mut ebb = EncryptedBoxBuilder::new(scheme);
    let eb = ebb
        .set_password(password)
        .add_fields(&opt.fields[..])
        .build()?;

    // encrypt
    let enc = eb
        .encrypt()
        .with_context(|_| format!("encryption failed!"))?;
    println!("{}", base64::encode(&enc[..]));

    Ok(())
}

/// This tool allows you to encrypt any number of fields
/// with AES (choosing from a few flavors). It relies on
/// the openssl implementation. Output is in base 64. See
/// https://docs.rs/openssl/0.9.17/openssl/symm/struct.Cipher.html
/// for more information.
#[derive(StructOpt, Debug)]
#[structopt(name = "encrypted-box", version = "0.2.6", author = "")]
struct Opt {
    /// Password for encryption/decryption
    #[structopt(short = "p", long = "password")]
    password: Option<String>,
    /// Path to password file for encryption/decryption (password option supersedes this option)
    #[structopt(
        long = "password-file",
        default_value = ".pass",
        raw(required = "false"),
        parse(from_os_str)
    )]
    path_to_password: PathBuf,
    /// Fields to add
    #[structopt(short = "f", long = "field", raw(required = "true"))]
    fields: Vec<String>,
    /// Encryption scheme
    /// Options:     
    /// [0. AES 128 ECB ;
    /// 1. AES 128 CBC ;
    /// 2. AES 128 CTR ;
    /// 3. AES 128 OFB ;
    /// 4. AES 192 ECB ;
    /// 5. AES 192 CBC ;
    /// 6. AES 192 CTR ;
    /// 7. AES 192 OFB ;
    /// 8. AES 256 ECB ;
    /// 9. AES 256 CBC ;
    /// 10. AES 256 CTR ;
    /// 11. AES 256 OFB]
    #[structopt(short = "s", long = "scheme", default_value = "0")]
    scheme: u32,
}

fn get_password(password: Option<String>, path: PathBuf) -> Result<String, std::io::Error> {
    let password = match password {
        Some(pass) => pass,
        None => fs::read_to_string(path.to_str().unwrap())?,
    };
    Ok(password)
}
