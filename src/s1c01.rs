
extern crate base64;
extern crate hex;

use errors::{Possibly, CPError};

pub fn hex_to_b64(hex: &str) -> Possibly<String> {
    let bytes: Possibly<Vec<u8>> =
            hex::decode(&hex)
            .map_err(|err| CPError::HexConversion(err));

    bytes.map(|bs| base64::encode(&bs))
}

#[test]
fn test_hex_to_b64() {
    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b6\
                         5206120706f69736f6e6f7573206d757368726f6f6d";

    const OUTPUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3Vz\
                          IG11c2hyb29t";
    let b64 = hex_to_b64(INPUT).unwrap();
    assert_eq!(OUTPUT, b64);
}

