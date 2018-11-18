
extern crate hex;

const TARGET: &str  = "1c0111001f010100061a024b53535009181c";
const PARTNER: &str = "686974207468652062756c6c277320657965";

pub fn fixed_xor(target: &[u8], partner: &[u8]) -> Vec<u8> {
    target.iter()
        .zip(partner)
        .map(|(l, r)| l ^ r)
        .collect()
}

#[test]
fn test_fixed_xor() {
    let hex0 = hex::decode(TARGET).unwrap();
    let hex1 = hex::decode(PARTNER).unwrap();
    let xor = fixed_xor(&hex0, &hex1);
    let expected = "746865206b696420646f6e277420706c6179";
    assert_eq!(hex::encode(xor), expected)
}

