
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

pub fn s2c10() -> String {
    let mut handle = File::open("data/s2/q10_input.txt").unwrap();
    let mut buffer = String::new();

    let bsize = handle.read_to_string(&mut buffer);

    if let Err(err) = bsize {
        panic!("{}", err);
    }

    let ciphertext: String = buffer.chars()
            .filter(|&char| char != '\n')
            .collect();

    let ciphertext = base64::decode(&ciphertext).unwrap();

    let key = b"YELLOW SUBMARINE";

    let iv  = vec![0u8; BLOCK_SIZE];

    let message = aes_128_cbc_crypt(Mode::Decrypt, &key[..], &iv, &ciphertext);

    String::from_utf8(message).unwrap()
}

