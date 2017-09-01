
extern crate rand;
extern crate openssl;

use s1c07::aes_128_ecb_crypt;
use s2c09::pkcs;
use s2c10::aes_128_cbc_crypt;
use self::openssl::symm::Mode;
use self::rand::Rng;
use self::rand::distributions::{IndependentSample, Range};
use std::collections::HashSet;

const KEY_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16;

pub fn gen_bytes(size: usize) -> Vec<u8> {
    let mut rng    = rand::thread_rng();
    let mut buffer = Vec::with_capacity(size);

    for _ in 0..size {
        let byte: u8 = rng.gen();
        buffer.push(byte);
    }

    buffer
}

pub fn black_box_encrypter(message: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let between      = Range::new(5, 11);
    let prepend_size = between.ind_sample(&mut rng);
    let append_size  = between.ind_sample(&mut rng);
    let prepend      = gen_bytes(prepend_size);
    let append       = gen_bytes(append_size);

    let m_size = prepend_size + message.len() + append_size;
    let c_size = m_size + BLOCK_SIZE - m_size % BLOCK_SIZE;

    let mut ciphertext = Vec::with_capacity(c_size);

    ciphertext.extend_from_slice(&prepend);
    ciphertext.extend_from_slice(message);
    ciphertext.extend_from_slice(&append);

    ciphertext = pkcs(&ciphertext, c_size);

    let key = gen_bytes(KEY_SIZE);

    if rng.gen() {
        aes_128_ecb_crypt(Mode::Encrypt, &key, &ciphertext)
    } else {
        let iv = gen_bytes(KEY_SIZE);
        aes_128_cbc_crypt(Mode::Encrypt, &key, &iv, &ciphertext)
    }
}

pub fn ecb_detector(ciphertext: &[u8], size: usize) -> bool {
    let mut blocks = HashSet::new();

    for block in ciphertext.chunks(size) {
        if blocks.contains(block) {
            return true;
        }

        blocks.insert(block);
    }

    false
}

pub fn s2c11() -> String {
    let message = String::from(
        "Here I'm just gonna try something crazy and type a bunch of words.
        Like, enough words so that if I actually give decrypting this a shot,
        it has a reasonable chance of detecting ECB when it actually occurs
        This is actually more likely than it might initially seem; if the block
        size is just 16, so two consecutive characters anywhere in the message
        should encrypt to the same thing.  Interesting to see if the oracle
        will actually be able to bust it on this text.  So yeah, anyway, let's
        see what happens.  At the very least there are a bunch of double spaces
        at the end of sentences.

        Hmm that doesn't seem to be doing it though.  Somehow.  I'll check that
        function again in a second, but it seems like the easiest thing to do
        might just be to write more text, use some longer words, etc.  Maybe
        use some longer words again and again, you know.  Like sentences.  Or
        somehow.

        What if I were to just include the same exact text multiple times?

        What if I were to just include the same exact text multiple times?

        I said, what if I were to just include the same exact text multiple
        times?");

    let ciphertext = black_box_encrypter(message.as_bytes());

    if ecb_detector(&ciphertext, BLOCK_SIZE) {
        String::from("that's probably ECB-encrypted.")
    } else {
        String::from("that's probably CBC-encrypted.")
    }
}

