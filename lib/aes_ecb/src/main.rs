
extern crate base64;
extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read};

fn new_crypter_unpadded(
        cipher: Cipher,
        mode: Mode,
        key: &[u8],
        iv: Option<&[u8]>
        ) -> Crypter {
    let mut crypter = match Crypter::new(cipher, mode, key, iv) {
            Ok(val) => val,
            Err(err) => panic!("{}", err)
    };

    crypter.pad(false);

    crypter
}

// FIXME better command line args

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

    let mut crypter = new_crypter_unpadded(cipher, mode, key, iv);
    let mut result  = vec![0u8; decoded_len + cipher.key_len()];

    let decrypted_len = match crypter.update(&decoded, result.as_mut_slice()) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let output = &result[0..decrypted_len];

    println!("{}", String::from_utf8_lossy(output));
}

