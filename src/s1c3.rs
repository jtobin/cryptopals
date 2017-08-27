
extern crate hex;

use self::hex::FromHex;
use std::collections::HashMap;

const HASH: &'static str =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

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

pub fn s1c3() -> String {
    let mut bytes: Vec<u8> = FromHex::from_hex(&HASH).unwrap();

    let tallied = tally(bytes.clone());
    let max     = max_elem(tallied);

    for byte in bytes.iter_mut() { *byte ^= max - 32; }

    String::from_utf8(bytes).unwrap()
}

