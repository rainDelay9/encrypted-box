use sha2::{Digest, Sha256};

pub fn derive_key_from_password(password: &String) -> Vec<u8> {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.input(password.as_bytes());
    // read hash digest and consume hasher
    let result = hasher.result();
    let mut vec = Vec::new();
    vec.extend(result.as_slice());
    vec
}
