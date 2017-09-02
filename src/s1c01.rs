
extern crate base64;
extern crate hex;

use errors::CryptopalsError;
use self::hex::FromHex;

const INPUT: &str =
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6\
    f7573206d757368726f6f6d";

pub fn hex_to_b64(input: &str) -> Result<String, CryptopalsError> {
    let raw: Result<Vec<u8>, _> = FromHex::from_hex(&input)
            .map_err(|err| CryptopalsError::HexConversionError(err));

    raw.map(|contents| base64::encode(&contents))
}

pub fn s1c01() -> Result<String, CryptopalsError> {
    hex_to_b64(INPUT)
}

