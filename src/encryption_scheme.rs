pub trait EncryptionScheme {
    type Error;
    type Variant;

    fn new(v: &Self::Variant) -> Self;
    fn get_key_length(&self) -> usize;
    fn encrypt(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn decrypt(&self, key: &[u8], ctext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
