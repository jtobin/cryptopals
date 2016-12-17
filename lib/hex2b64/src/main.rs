extern crate rustc_serialize as serialize;

use serialize::base64::{self, ToBase64};
use serialize::hex::FromHex;
use std::io::{self, Read};

fn main() {
    let mut buffer = String::new();

    io::stdin().read_to_string(&mut buffer)
        .expect("hex2b64: bad input");

    let result = match buffer.from_hex() {
        Err(err) => panic!("hex2b64: {}", err),
        Ok(val)  => val.to_base64(base64::STANDARD),
    };

    println!("{}", result);
}
