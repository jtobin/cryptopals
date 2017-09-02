
extern crate hex;

use errors::CryptopalsError;
use self::hex::{FromHex, ToHex};

const TARGET: &str  = "1c0111001f010100061a024b53535009181c";
const PARTNER: &str = "686974207468652062756c6c277320657965";

pub fn fixed_xor(target: &[u8], partner: &[u8]) -> Vec<u8> {
    target.iter()
        .zip(partner)
        .map(|(l, r)| l ^ r)
        .collect()
}

pub fn s1c02() -> Result<String, CryptopalsError> {
    let target: Result<Vec<u8>, _> = FromHex::from_hex(&TARGET)
            .map_err(|err| CryptopalsError::HexConversionError(err));

    let target = match target {
        Ok(val) => val,
        Err(err) => return Err(err)
    };

    let partner: Result<Vec<u8>, _> = FromHex::from_hex(&PARTNER)
            .map_err(|err| CryptopalsError::HexConversionError(err));

    let partner = match partner {
        Ok(val) => val,
        Err(err) => return Err(err)
    };

    Ok(fixed_xor(&target, &partner).to_hex())
}
