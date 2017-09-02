
extern crate base64;
extern crate openssl;

use s1c07::aes_128_ecb_crypt;
use s2c09::pad_pkcs7;
use self::openssl::symm::Mode;

const BLOCK_SIZE: usize = 16;

const APPENDER: &str =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
    YnkK";

// FIXME (jtobin)
//
// Consider just adjusting the original encryption function such that messages
// are always padded appropriately.
//
pub fn aes_128_ecb_crypt_padding(message: &[u8], key: &[u8]) -> Vec<u8> {
    let m_size = message.len() + APPENDER.len();
    let c_size = m_size + BLOCK_SIZE - m_size % BLOCK_SIZE;

    let mut ciphertext = Vec::with_capacity(c_size);

    let appender = base64::decode(APPENDER).unwrap();

    ciphertext.extend_from_slice(message);
    ciphertext.extend_from_slice(&appender);

    ciphertext = pad_pkcs7(&ciphertext, c_size);

    aes_128_ecb_crypt(Mode::Encrypt, key, &ciphertext)
}

pub fn blocksize_oracle(message: &[u8], key: &[u8]) -> usize {
    let mut input = Vec::new();
    let head = message[0];

    loop {
        input.push(head);

        let ciphertext = aes_128_ecb_crypt_padding(&message, &key);

        if ciphertext.len() > message.len() {
            return ciphertext.len() - message.len();
        }
    }
}

pub fn s2c12() -> String {

    let tester = String::from("hurbitty gurbitty");
    let key    = String::from("YELLOW SUBMARINE");
    let foo    = blocksize_oracle(&tester.as_bytes(), &key.as_bytes());

    println!("{}", foo);

    String::from("foo")
}

