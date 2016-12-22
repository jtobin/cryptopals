extern crate rustc_serialize as serialize;

use serialize::hex::{FromHex};
use std::env;
use std::io::{self, Read};
use std::string::String;

fn main() {
    // deal with args
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("USAGE: echo FOO | ./single_byte_xor BYTE");
        return ()
    }

    let supplied_string = &args[1];
    let supplied_byte   = match supplied_string.parse::<u8>() {
        Err(err) => panic!("single_byte_xor: failed parse, {}", err),
        Ok(val)  => val,
    };

    // deal with stdin
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer)
        .expect("single_byte_xor: bad input");

    let mut decoded = match buffer.from_hex() {
        Err(err) => panic!("single_byte_xor: {}", err),
        Ok(val)  => val,
    };

    for byte in decoded.iter_mut() { *byte ^= supplied_byte; }

    let decrypted = match String::from_utf8(decoded) {
        Err(err) => panic!("single_byte_xor: {}", err),
        Ok(val)  => val,
    };

    println!("original: {}", &buffer);
    println!("xored with: {} ({})", supplied_string, supplied_byte as char);
    println!("decrypted: {}", decrypted);
}
