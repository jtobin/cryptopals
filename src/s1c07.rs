
extern crate base64;
extern crate openssl;

use self::openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::prelude::Read;
use std::string::String;

pub fn new_crypter_unpadded(
        cipher: Cipher,
        mode: Mode,
        key: &[u8],
        iv: Option<&[u8]>
        ) -> Crypter {

    let mut crypter = Crypter::new(cipher, mode, key, iv).unwrap();

    crypter.pad(false);

    crypter
}

pub fn aes_128_ecb_crypt(mode: Mode, key: &[u8], content: &[u8]) -> Vec<u8> {
    let cipher     = Cipher::aes_128_ecb();
    let iv         = None;
    let bsize      = content.len() + cipher.key_len();
    let mut buffer = vec![0; bsize];

    let mut crypter = new_crypter_unpadded(cipher, mode, key, iv);

    let crypted_len   = crypter.update(content, &mut buffer).unwrap();
    let finalized_len = crypter.finalize(&mut buffer).unwrap();

    buffer[0..crypted_len + finalized_len].to_vec()
}

pub fn s1c07() -> String {
    let mut handle = File::open("data/s1/q7_input.txt").unwrap();
    let mut buffer = String::new();

    let _ = handle.read_to_string(&mut buffer).unwrap();

    let ciphertext: String = buffer.chars()
            .filter(|&c| c != '\n')
            .collect();

    let ciphertext = base64::decode(&ciphertext).unwrap();

    let key = b"YELLOW SUBMARINE";

    let message = aes_128_ecb_crypt(Mode::Decrypt, &key[..], &ciphertext);

    String::from_utf8(message).unwrap()
}

