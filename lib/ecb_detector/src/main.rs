
extern crate base64;

use std::collections::HashSet;
use std::io::{self, Read};

const KEY_SIZE: usize = 16;

fn ecb_detector(ciphertext: &[u8], size: usize) -> bool {
    let mut blocks = HashSet::new();

    for block in ciphertext.chunks(size) {
        if blocks.contains(block) {
            return true;
        }

        blocks.insert(block);
    }

    false
}

fn main() {
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer).expect("ecb_decoder");

    let decoded = match base64::decode(&buffer) {
        Ok(val)  => val,
        Err(err) => panic!("{}", err)
    };

    let ecb = ecb_detector(&decoded[..], KEY_SIZE);

    if ecb {
        println!("likely ecb");
    } else {
        println!("likely cbc");
    }
}

