
extern crate hex;
extern crate base64;

use self::hex::{FromHex, FromHexError};
use std::process;

const INPUT: &str =
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6\
    f7573206d757368726f6f6d";

pub fn hex_to_b64(input: &str) -> Result<String, FromHexError> {
    let raw: Result<Vec<u8>, _> = FromHex::from_hex(&input);
    raw.map(|contents| base64::encode(&contents))
}

pub fn s1c1() -> String {
    hex_to_b64(&INPUT).unwrap_or_else(|err| {
            println!("error (cryptopals): {}", err);
            process::exit(1);
    })
}

