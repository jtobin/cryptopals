
extern crate base64;
extern crate openssl;

use self::openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::prelude::Read;
use std::str;
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

pub fn aes_128_ecb_decrypt(key: &str, ciphertext: &str) -> String {
    let key: Vec<u8>        = base64::decode(&key).unwrap();
    let ciphertext: Vec<u8> = base64::decode(&ciphertext).unwrap();

    let message = aes_128_ecb_crypt(Mode::Decrypt, &key[..], &ciphertext[..]);

    base64::encode(&message)
}

pub fn aes_128_ecb_encrypt(key: &str, message: &str) -> String {
    let key: Vec<u8>     = base64::decode(&key).unwrap();
    let message: Vec<u8> = base64::decode(&message).unwrap();

    let ciphertext = aes_128_ecb_crypt(Mode::Encrypt, &key[..], &message[..]);

    base64::encode(&ciphertext)
}

pub fn s1c7() -> String {
    let key        = base64::encode("YELLOW SUBMARINE");
    let mut handle = File::open("data/s1/q7_input.txt").unwrap();
    let mut buffer = String::new();

    let bsize = handle.read_to_string(&mut buffer);

    if let Err(err) = bsize {
        panic!("{}", err);
    }

    let trimmed: String = buffer.chars()
            .filter(|&char| char != '\n')
            .collect();

    let decrypted = aes_128_ecb_decrypt(&key, &trimmed);
    let decrypted = base64::decode(&decrypted).unwrap();

    String::from_utf8(decrypted).unwrap()
}

