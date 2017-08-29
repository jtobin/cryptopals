
extern crate hex;

use self::hex::{FromHex, ToHex};

const TARGET: &str  = "1c0111001f010100061a024b53535009181c";
const PARTNER: &str = "686974207468652062756c6c277320657965";

fn fixed_xor(target: &str, partner: &str) -> String {

    assert_eq!(target.len(), partner.len());

    let mut l: Vec<u8> = FromHex::from_hex(&target).unwrap();
    let r: Vec<u8>     = FromHex::from_hex(&partner).unwrap();

    for (lb, rb) in l.iter_mut().zip(r) { *lb ^= rb }

    l.to_hex()
}

pub fn s1c2() -> String {
    fixed_xor(&TARGET, &PARTNER)
}
