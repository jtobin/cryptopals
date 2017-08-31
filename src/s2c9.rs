
extern crate base64;

pub fn pkcs(block: &[u8], size: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(size);
    let len     = block.len();

    let padding_len = if len < size { (size - len) as u8 } else { 0 };
    let padding     = vec![padding_len; padding_len as usize ];

    vec.extend_from_slice(block);
    vec.extend_from_slice(&padding);
    vec
}

pub fn s2c9() -> String {
    let message = "YELLOW_SUBMARINE".as_bytes();
    let padded  = pkcs(message, 20);

    base64::encode(&padded)
}
