extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use std::collections::HashMap;
use std::env;
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
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("USAGE: ./charfreq HEX");
        return ()
    }

    let supplied_string     = &args[1];
    let supplied_string_len = supplied_string.len();

    let decoded = match supplied_string.from_hex() {
        Err(err) => panic!("charfreq: {} ({})", err, supplied_string_len),
        Ok(val)  => val,
    };

    let mut results: Vec<(u8, u8)> = tally(decoded).into_iter().collect();
    results.sort_by(|a, b| b.1.cmp(&a.1));

    let best: Vec<(u8, u8)> = results.into_iter().take(5).collect();

    println!("original: {}", &supplied_string);
    println!("byte (frequency)");
    println!("----------------");
    for (val, count) in best {
        println!("{}: {} (freq: {})", val, val as char, count);
    }
}

