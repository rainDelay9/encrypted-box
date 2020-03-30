# encrypted-box
This project holds the encrypted-box library as well as the encrypted-box cli.
The main functionality is the encryption of an unknown amount of fields.

## Quickstart

### Build
use 
```
cargo build [--release]
```
### Test
use 
```
cargo test
```
### CLI
use
```
path-to-encrypted-box-bin/encrypted-box --help
```
for instructions on how to use the cli,
or
```
cargo run -- [parameters for cli]
```
for another method of running.


## Organization of the project
The project is divided into a few modules:
### encryption-scheme (encryption-scheme.rs)
Holds definition of EncryptionScheme trait which is needed to be implemented by any encryption scheme encapsulated in encrypted-box.
### encrypted-box (encrypted-box.rs)
Holds the main struct EncryptedBox which is initialized by EncryptedBoxBuilder. Generic type T must implement EncryptionScheme trait.

### encrypted-box-builder (encrypted-box-builder.rs)
The module is a builder for the encrypted-box object.
It was built according to [this](https://doc.rust-lang.org/1.0.0/style/ownership/builders.html) using the non-consuming template.
It is also generic with type T which must implement EncryptionScheme trait.

### kdf (kdf.rs)
A very (very) basic functionality for deriving keys using SHA512. (this should be replaced by a more serious one, or even added to EncryptionScheme trait so that each scheme can derive its own keys however it wants/needs them)

### cli (cli.rs)
A command line tool for encrypted-box. Tests for cli are in tests/cli.rs.

### openssl AES (openssl_aes/)
A wrapper for the openssl AES Rust library. Actual Wrapper is openssl_aes/wrapper.rs, definitions in openssl_aes/defs.rs and errors in openssl_aes.rs.

---

#### CI/CD
This repository has a ```.travis.yml``` file. It is a configuration for [Travis](https://travis-ci.com/) CI/CD tool which is very easy and recommended.
