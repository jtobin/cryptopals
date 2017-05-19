
extern crate base64;
extern crate clap;
extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{self, Read};
use clap::{App, Arg};

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

fn main() {
    let args = App::new("aes_ecb")
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

    io::stdin().read_to_string(&mut buffer).expect("aes_ecb");

    let decoded = match base64::decode(&buffer) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let decoded_len = decoded.len();

    let cipher = Cipher::aes_128_ecb();

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
            Some(text) => Some(text.as_bytes()),
            None       => None,
    };

    let mut crypter = new_crypter_unpadded(cipher, mode, key, iv);
    let mut result  = vec![0u8; decoded_len + cipher.key_len()];

    let decrypted_len = match crypter.update(&decoded, result.as_mut_slice()) {
            Ok(val)  => val,
            Err(err) => panic!("{}", err)
    };

    let output = &result[0..decrypted_len];

    println!("{}", String::from_utf8_lossy(output));
}

