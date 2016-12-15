extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

const HASH: &'static str =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn decode(s: &str) -> Vec<u8> {
    s.from_hex().unwrap()
}

fn tally(vec: Vec<u8>) -> HashMap<u8, u8> {
    let mut hashmap = HashMap::new();

    for byte in vec {
        let count = hashmap.entry(byte).or_insert(0);
        *count += 1;
    }

    hashmap
}

fn max_elem(hashmap: HashMap<u8, u8>) -> u8 {
    let mut max = 0;
    let mut max_index = 0;

    for (byte, count) in hashmap.iter() {
        if count > &max {
            max       = *count;
            max_index = *byte;
        }
    }

    max_index
}

fn main() {
    let decoded = decode(HASH);
    let tallied = tally(decoded);
    let max     = max_elem(tallied);

    let mut i_am_a_rust_noob = decode(HASH);

    for byte in i_am_a_rust_noob.iter_mut() { *byte ^= max; }

    let decrypted = String::from_utf8(i_am_a_rust_noob).unwrap();
    println!("{}", HASH);
    println!("{}", decrypted);
}


