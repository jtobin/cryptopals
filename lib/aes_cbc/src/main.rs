
// hat tip to ttaubert/rust-cryptopals for lots of help here

extern crate base64;
extern crate clap;
extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read};
use clap::{App, Arg};

fn fixed_xor(target: Vec<u8>, partner: Vec<u8>) -> Vec<u8> {
    assert_eq!(target.len(), partner.len());

    target
        .iter()
        .zip(partner)
        .map(|(&l, r)| l ^ r)
        .collect()
}

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

fn ecb_128_crypt(mode: Mode, key: &[u8], text: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let iv     = None;

    let mut crypter = new_crypter_unpadded(cipher, mode, key, iv);
    let mut result  = vec![0; text.len() + cipher.key_len()];

    let decrypted_len = match crypter.update(&text, result.as_mut_slice()) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    (&result[0..decrypted_len]).to_vec()
}

fn ecb_128_encrypt(key: &[u8], text: &[u8]) -> Vec<u8> {
    ecb_128_crypt(Mode::Encrypt, key, text)
}

fn ecb_128_decrypt(key: &[u8], text: &[u8]) -> Vec<u8> {
    ecb_128_crypt(Mode::Decrypt, key, text)
}

fn cbc_128_encrypt(key: &[u8], text: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let mut iv = iv;
    let mut ciphertext = Vec::with_capacity(text.len());

    for block in text.chunks(16) {
        let xored     = fixed_xor(iv, block.to_vec());
        let encrypted = ecb_128_encrypt(key, xored.as_slice());

        ciphertext.extend(encrypted.clone());
        iv = encrypted;
    }

    ciphertext
}

fn cbc_128_decrypt(key: &[u8], text: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let mut iv    = iv;
    let mut plain = Vec::with_capacity(text.len());

    for block in text.chunks(16) {
        let decrypted = ecb_128_decrypt(key, block);
        plain.extend(fixed_xor(decrypted, iv));

        iv = block.to_vec();
    }

    plain
}

fn main() {
    let args = App::new("aes_cbc")
                    .version("0.1")
                    .about("AES ECB/CBC tools")
                    .arg(Arg::with_name("key")
                            .short("k")
                            .long("key")
                            .value_name("KEY")
                            .takes_value(true)
                            .required(true))
                    .arg(Arg::with_name("mode")
                            .short("e")
                            .long("encrypt")
                            .help("encrypt (instead of decrypt)"))
                    .arg(Arg::with_name("iv")
                            .short("i")
                            .long("iv")
                            .value_name("INIT")
                            .takes_value(true)
                            .help("initial value"))
                    .get_matches();

    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer).expect("aes_cbc");

    let decoded = match base64::decode(&buffer) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let mode = match args.occurrences_of("mode") {
            0 => Mode::Decrypt,
            _ => Mode::Encrypt,
    };

    let key = match args.value_of("key") {
            Some(text) =>
                if text.len() == 16 {
                    text.as_bytes()
                } else {
                    panic!("invalid key length!");
                },
            None => panic!("no key provided.")
    };

    let iv = match args.value_of("iv") {
            Some(text) => text.as_bytes().to_vec(),
            None       => (&[0u8; 16]).to_vec(),
    };

    let output = match mode {
            Mode::Decrypt => cbc_128_decrypt(&decoded[..], key, iv),
            Mode::Encrypt => cbc_128_encrypt(&decoded[..], key, iv),
    };

    match mode {
        Mode::Decrypt => println!("{}", String::from_utf8_lossy(&output)),
        Mode::Encrypt => println!("{}", base64::encode(&output)),
    };
}

