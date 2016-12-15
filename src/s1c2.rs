extern crate rustc_serialize;

use rustc_serialize::hex::{ToHex, FromHex};

fn fixed_xor(target: &str, partner: &str) -> String {
    assert_eq!(target.len(), partner.len());

    let mut l = target.from_hex().unwrap();
    let r     = partner.from_hex().unwrap();

    for (lb, rb) in l.iter_mut().zip(r) { *lb ^= rb }

    l.to_hex()
}

fn main() {
    let left  = "1c0111001f010100061a024b53535009181c";
    let right = "686974207468652062756c6c277320657965";

    let result = fixed_xor(left, right);

    println!("{}", result);
}

