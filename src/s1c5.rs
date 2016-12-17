extern crate rustc_serialize as serialize;

use serialize::hex::{ToHex};
use std::vec::Vec;

const STRING: &'static str =
    "Burning 'em, if you ain't quick and nimble\n\
    I go crazy when I hear a cymbal";

fn repeating_key_xor(text: &str, key: &str) -> String {
    let text_bytes = text.as_bytes();
    let key_bytes  = key.as_bytes();

    let mut xored: Vec<u8> = vec![0; text_bytes.len()];

    for (idx, val) in text_bytes.iter().enumerate() {
        let byte_idx   = idx % key_bytes.len();
            xored[idx] = val ^ key_bytes[byte_idx];
    }

    xored.to_hex()
}

fn main() {
    println!("{}", STRING);
    println!("{}", repeating_key_xor(STRING, "ICE"));
}

// to read from stdin:
//
// use std::io::{self, Read};
//
// let mut buffer = String::new();
//
//  io::stdin().read_to_string(&mut buffer)
//      .expect("Couldn't read.");
//
//  println!("{}", &buffer);
//  println!("{}", repeating_key_xor(&buffer, "ICE"));

