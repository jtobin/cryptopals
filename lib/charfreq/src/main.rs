extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use std::collections::HashMap;
use std::io::{self, Read};
use std::string::String;
use std::vec::Vec;

fn tally(vec: Vec<u8>) -> HashMap<u8, u8> {
    let mut hashmap = HashMap::new();

    for byte in vec {
        let count = hashmap.entry(byte).or_insert(0);
        *count += 1;
    }

    hashmap
}

fn main() {
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer)
        .expect("charfreq: bad input");

    let decoded = match buffer.from_hex() {
        Err(err) => panic!("charfreq: {}", err),
        Ok(val)  => val,
    };

    let mut results: Vec<(u8, u8)> = tally(decoded).into_iter().collect();
    results.sort_by(|a, b| b.1.cmp(&a.1));

    let best: Vec<(u8, u8)> = results.into_iter().take(5).collect();

    println!("byte (frequency)");
    println!("----------------");
    for (val, count) in best { println!("{} ({})", val, count); }
}

