
extern crate base64;
extern crate openssl;
extern crate rand;

use s1c07;
use s2c09::pad_pkcs7;
use s2c11;
use self::openssl::symm::Mode;
use self::rand::{Rng, SeedableRng, StdRng};
use std::ops::Range;
use std::iter::{FromIterator, repeat};

const BLOCK_SIZE: usize = 16;

pub fn aes_128_ecb_crypt(mode: Mode, message: &[u8], key: &[u8]) -> Vec<u8> {
    let m_size = message.len();
    let c_size = m_size + BLOCK_SIZE - m_size % BLOCK_SIZE;

    let ciphertext = pad_pkcs7(message, c_size);

    s1c07::aes_128_ecb_crypt(mode, key, &ciphertext)
}

pub fn gen_bytes_from_seed(size: usize, seed: &[usize]) -> Vec<u8> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut buffer      = Vec::with_capacity(size);

    for _ in 0..size {
        let byte: u8 = rng.gen();
        buffer.push(byte);
    }

    buffer
}

pub fn block_size_oracle<F>(f: F) -> usize
    where F: Fn(&[u8]) -> Vec<u8> {

    let mut input = Vec::new();
    let byte = 'A' as u8;

    loop {
        input.push(byte);

        let ciphertext = f(&input);

        if ciphertext.len() > input.len() {
            return ciphertext.len() - input.len() + 1;
        }
    }
}

pub fn padding_oracle<F>(f: F) -> usize
    where F: Fn(&[u8]) -> Vec<u8> {

    let mut input = Vec::new();

    let ciphertext = f(&input);
    let c_size     = ciphertext.len();

    let byte = 'A' as u8;

    loop {
        input.push(byte);

        let new_ciphertext = f(&input);

        if new_ciphertext.len() > c_size {
            return input.len();
        }
    }
}

pub fn encryption_oracle(injected: &[u8]) -> Vec<u8> {
    let message = base64::decode(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK").unwrap();

    let m_size = injected.len() + message.len();

    let mut augmented_message = Vec::with_capacity(m_size);

    augmented_message.extend_from_slice(injected);
    augmented_message.extend_from_slice(&message);

    let key = gen_bytes_from_seed(BLOCK_SIZE, &[1, 1, 2, 3, 5, 8, 13]);

    aes_128_ecb_crypt(Mode::Encrypt, &augmented_message, &key)
}

// lifted this just about verbatim from ttaubert/rust-cryptopals
// his looping method is pretty smahhhhhhhhhht
pub fn single_byte_ecb_decrypt<F>(f: F) -> Vec<u8>
        where F: Fn(&[u8]) -> Vec<u8> {

    let b_size  = block_size_oracle(&f);
    let is_ecb  = s2c11::ecb_oracle(&f, b_size); // FIXME
    let padding = padding_oracle(&f);

    let ciphertext = f(&[]);
    let c_size     = ciphertext.len();

    let mut input  = Vec::from_iter(repeat(b'A').take(c_size));

    let guess = Range { start: c_size - b_size, end: c_size };

    for index in 0..c_size - padding {
        if index % b_size == 0 {
            let block = input[guess.clone()].to_vec();
            input.extend(block);
        }

        input.remove(0);

        let start  = c_size + index - index % b_size;
        let target = Range { start: start, end: start + b_size };

        for byte in 0..256 {
            input[c_size - 1] = byte as u8;
            let probe = f(&input);

            if probe[guess.clone()] == probe[target.clone()] {
                break;
            }
        }

    }

    input[padding..c_size].to_vec()
}

pub fn s2c12() -> String {
    let message = single_byte_ecb_decrypt(encryption_oracle);

    String::from_utf8(message).unwrap()
}

