extern crate base64;
extern crate openssl;

use base64::decode;
use openssl::symm::{Cipher, Crypter};
use openssl::symm::Mode;
use std::io::{self, Read};
use std::str;

fn main() {
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer)
        .expect("aes_ecb");

    let decoded     = &decode(&buffer).unwrap();
    let decoded_len = decoded.len();

    let mut crypter = Crypter::new(
              Cipher::aes_128_ecb()
            , Mode::Decrypt
            , b"YELLOW SUBMARINE"
            , None).unwrap();

    crypter.pad(false);

    let mut result = vec![0u8; 2896];

    let c_len  = crypter.update(&decoded[..decoded_len], result.as_mut_slice()).unwrap();
    let output = &result[1..c_len];

    println!("{:?}", String::from_utf8_lossy(output));
}

