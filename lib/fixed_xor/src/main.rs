extern crate rustc_serialize;

use rustc_serialize::hex::{ToHex, FromHex};
use std::env;

fn fixed_xor(target: &str, partner: &str) -> String {
    assert_eq!(target.len(), partner.len());

    let mut l = target.from_hex().unwrap();
    let r     = partner.from_hex().unwrap();

    for (lb, rb) in l.iter_mut().zip(r) { *lb ^= rb }

    l.to_hex()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("USAGE: ./fixed_xor HEX HEX");
        return ()
    }

    let left  = &args[1];
    let right = &args[2];

    let result = fixed_xor(left, right);

    println!("{}", result);
}

