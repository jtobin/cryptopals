
extern crate base64;
extern crate hex;
extern crate openssl;

use s1c07::aes_128_ecb_crypt;
use std::fs::File;
use self::openssl::symm::Mode;
use std::io::Read;
use std::str;

const BLOCK_SIZE: usize = 16;

fn fixed_xor(target: &[u8], partner: &[u8]) -> Vec<u8> {
    target.iter()
        .zip(partner)
        .map(|(l, r)| l ^ r)
        .collect()
}

pub fn aes_128_cbc_crypt(
          mode: Mode
        , key: &[u8]
        , iv: &[u8]
        , contents: &[u8]
        ) -> Vec<u8> {

    let mut buffer = Vec::with_capacity(contents.len());

    match mode {
        Mode::Encrypt => {
            contents.chunks(BLOCK_SIZE).fold(iv.to_vec(),
                |i, block| {
                    let xored     = fixed_xor(&i, block);
                    let encrypted = aes_128_ecb_crypt(mode, key, &xored);

                    buffer.extend(&encrypted);
                    encrypted
                });
        },
        Mode::Decrypt => {
            contents.chunks(BLOCK_SIZE).fold(iv.to_vec(),
                |i, block| {
                    let decrypted = aes_128_ecb_crypt(mode, key, block);
                    let xored = fixed_xor(&decrypted, &i);

                    buffer.extend(&xored);
                    block.to_vec()
                });
        }
    }

    buffer
}

pub fn aes_128_cbc_decrypt(key: &str, iv: &str, ciphertext: &str) -> String {
    let key: Vec<u8>        = base64::decode(&key).unwrap();
    let iv:  Vec<u8>        = base64::decode(&iv).unwrap();
    let ciphertext: Vec<u8> = base64::decode(&ciphertext).unwrap();

    let message =
        aes_128_cbc_crypt(Mode::Decrypt, &key[..], &iv[..], &ciphertext[..]);

    base64::encode(&message)
}

pub fn aes_128_cbc_encrypt(key: &str, iv: &str, message: &str) -> String {
    let key: Vec<u8>        = base64::decode(&key).unwrap();
    let iv:  Vec<u8>        = base64::decode(&iv).unwrap();
    let message: Vec<u8>    = base64::decode(&message).unwrap();

    let ciphertext =
        aes_128_cbc_crypt(Mode::Encrypt, &key[..], &iv[..], &message[..]);

    base64::encode(&ciphertext)
}


pub fn s2c10() -> String {
    let key        = base64::encode("YELLOW SUBMARINE");
    let mut handle = File::open("data/s2/q10_input.txt").unwrap();
    let mut buffer = String::new();

    let bsize = handle.read_to_string(&mut buffer);

    if let Err(err) = bsize {
        panic!("{}", err);
    }

    let trimmed: String = buffer.chars()
            .filter(|&char| char != '\n')
            .collect();

    let iv = vec![0u8; BLOCK_SIZE];
    let iv = base64::encode(&iv);

    let decrypted = aes_128_cbc_decrypt(&key, &iv, &trimmed);
    let decrypted = base64::decode(&decrypted).unwrap();

    String::from_utf8(decrypted).unwrap()
}

