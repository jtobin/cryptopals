extern crate rustc_serialize as serialize;

use serialize::hex::{ToHex};
use std::env;
use std::io::{self, Read};
use std::string::String;
use std::vec::Vec;

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
    // deal with args
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("USAGE: echo FOO | ./repeating_key_xor KEY");
        return ()
    }

    let supplied_key = &args[1];

    // deal with stdin
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer)
        .expect("repeating_key_xor: bad input");

    let xored = repeating_key_xor(&buffer, &supplied_key);

    println!("original: \n{}", &buffer);
    println!("xored with: {}", supplied_key);
    println!("result: \n{}", xored);

}
