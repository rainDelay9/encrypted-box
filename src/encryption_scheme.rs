pub trait EncryptionScheme {
    type Error;
    type Variant;

    // get a new scheme based on a variant of the original scheme
    fn new(v: &Self::Variant) -> Self;

    // get the key length of this scheme
    fn get_key_length(&self) -> usize;

    // encrypt msg using key
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error>;

    // decrypt ciphertext using key
    fn decrypt(&self, key: &[u8], ctext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
