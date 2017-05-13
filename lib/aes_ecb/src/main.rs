
extern crate base64;
extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read};

fn main() {
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer).expect("aes_ecb");

    let decoded = match base64::decode(&buffer) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let decoded_len = decoded.len();

    let cipher = Cipher::aes_128_ecb();
    let mode   = Mode::Decrypt;
    let key    = b"YELLOW SUBMARINE";
    let iv     = None;

    let mut crypter = match Crypter::new(cipher, mode, key, iv) {
            Ok(val) => val,
            Err(err) => panic!("{}", err)
    };

    crypter.pad(false);

    let mut result = vec![0u8; decoded_len + cipher.key_len()];

    let decrypted_len = match crypter.update(&decoded, result.as_mut_slice()) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let output = &result[1..decrypted_len];

    println!("{}", String::from_utf8_lossy(output));
}

