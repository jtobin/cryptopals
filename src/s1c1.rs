extern crate rustc_serialize as serialize;

// tips:
//
// always operate on raw bytes, never encoded strings
// only use hex and base64 for pretty printing

use serialize::base64::{self, ToBase64};
use serialize::hex::FromHex;

fn main() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b652061207\
                06f69736f6e6f7573206d757368726f6f6d";

    let result = input.from_hex().unwrap().to_base64(base64::STANDARD);

    println!("{}", result);
}
