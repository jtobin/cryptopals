
extern crate base64;
extern crate openssl;

use s1c07::aes_128_ecb_crypt;
use s2c09::pkcs;
use s2c11;
use self::openssl::symm::Mode;

const BLOCK_SIZE: usize = 16;

const APPENDER: &str =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK";

pub fn mystery_crypter(message: &[u8], key: &[u8]) -> Vec<u8> {
    let m_size = message.len() + APPENDER.len();
    let c_size = m_size + BLOCK_SIZE - m_size % BLOCK_SIZE;

    let mut ciphertext = Vec::with_capacity(c_size);

    let appender = base64::decode(APPENDER).unwrap();

    ciphertext.extend_from_slice(message);
    ciphertext.extend_from_slice(&appender);

    ciphertext = pkcs(&ciphertext, c_size);

    aes_128_ecb_crypt(Mode::Encrypt, key, &ciphertext)
}

pub fn s2c12() -> String {
    String::from("foo")
}

