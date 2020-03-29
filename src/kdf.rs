use sha2::{Digest, Sha512};

pub fn derive_key_from_password(password: &String, key_len: usize) -> Vec<u8> {
    // create a Sha256 object
    let mut hasher = Sha512::new();
    // write input message
    hasher.input(password.as_bytes());
    // read hash digest and consume hasher
    let result = hasher.result();
    // build result vector
    let mut vec = Vec::new();
    vec.extend(result.as_slice());
    vec.truncate(key_len);
    vec
}
