
extern crate hex;

use std::collections::HashMap;
use std::f32;
use std::u8;

fn tally(vec: Vec<u8>) -> HashMap<u8, u8> {
    let mut hashmap = HashMap::new();

    for byte in vec {
        let count = hashmap.entry(byte).or_insert(0);
        *count += 1;
    }

    hashmap
}

fn normalize(hashmap: HashMap<u8, u8>) -> HashMap<u8, f32> {
    let total = hashmap.iter().fold(0.0, |sum, (_, val)| sum + *val as f32);

    hashmap.iter()
        .map(|(&key, val)| (key, *val as f32 / total))
        .collect()
}

fn frequency_distribution(vec: Vec<u8>) -> HashMap<u8, f32> {
    let tallied = tally(vec);
    normalize(tallied)
}

pub fn freqs_ascii() -> HashMap<u8, f32> {
    [ (9, 0.000057)
    , (23, 0.000000)
    , (32, 0.171662)
    , (33, 0.000072)
    , (34, 0.002442)
    , (35, 0.000179)
    , (36, 0.000561)
    , (37, 0.000160)
    , (38, 0.000226)
    , (39, 0.002447)
    , (40, 0.002178)
    , (41, 0.002233)
    , (42, 0.000628)
    , (43, 0.000215)
    , (44, 0.007384)
    , (45, 0.013734)
    , (46, 0.015124)
    , (47, 0.001549)
    , (48, 0.005516)
    , (49, 0.004594)
    , (50, 0.003322)
    , (51, 0.001847)
    , (52, 0.001348)
    , (53, 0.001663)
    , (54, 0.001153)
    , (55, 0.001030)
    , (56, 0.001054)
    , (57, 0.001024)
    , (58, 0.004354)
    , (59, 0.001214)
    , (60, 0.001225)
    , (61, 0.000227)
    , (62, 0.001242)
    , (63, 0.001474)
    , (64, 0.000073)
    , (65, 0.003132)
    , (66, 0.002163)
    , (67, 0.003906)
    , (68, 0.003151)
    , (69, 0.002673)
    , (70, 0.001416)
    , (71, 0.001876)
    , (72, 0.002321)
    , (73, 0.003211)
    , (74, 0.001726)
    , (75, 0.000687)
    , (76, 0.001884)
    , (77, 0.003529)
    , (78, 0.002085)
    , (79, 0.001842)
    , (80, 0.002614)
    , (81, 0.000316)
    , (82, 0.002519)
    , (83, 0.004003)
    , (84, 0.003322)
    , (85, 0.000814)
    , (86, 0.000892)
    , (87, 0.002527)
    , (88, 0.000343)
    , (89, 0.000304)
    , (90, 0.000076)
    , (91, 0.000086)
    , (92, 0.000016)
    , (93, 0.000088)
    , (94, 0.000003)
    , (95, 0.001159)
    , (96, 0.000009)
    , (97, 0.051880)
    , (98, 0.010195)
    , (99, 0.021129)
    , (100, 0.025071)
    , (101, 0.085771)
    , (102, 0.013725)
    , (103, 0.015597)
    , (104, 0.027444)
    , (105, 0.049019)
    , (106, 0.000867)
    , (107, 0.006753)
    , (108, 0.031750)
    , (109, 0.016437)
    , (110, 0.049701)
    , (111, 0.057701)
    , (112, 0.015482)
    , (113, 0.000747)
    , (114, 0.042586)
    , (115, 0.043686)
    , (116, 0.063700)
    , (117, 0.020999)
    , (118, 0.008462)
    , (119, 0.013034)
    , (120, 0.001950)
    , (121, 0.011330)
    , (122, 0.000596)
    , (123, 0.000026)
    , (124, 0.000007)
    , (125, 0.000026)
    , (126, 0.000003)
    , (131, 0.000000)
    , (149, 0.006410)
    , (183, 0.000010)
    , (223, 0.000000)
    , (226, 0.000000)
    , (229, 0.000000)
    , (230, 0.000000)
    , (237, 0.000000)
    ].iter().cloned().collect()
}

fn mse(expected: HashMap<u8, f32>, observed: HashMap<u8, f32>) -> f32 {
    let mut result = HashMap::new();

    for (key, val) in expected.iter() {
        if observed.contains_key(key) {
            let tval   = observed.get(key).unwrap();
            let sqdiff = (tval - val).powf(2.0);
            result.insert(key, sqdiff);
        }
    }

    let size = result.len();

    result.iter().fold(0.0, |sum, (_, val)| sum + val / size as f32)
}

fn score(input: &[u8]) -> f32 {
    mse(freqs_ascii(), frequency_distribution(input.to_vec()))
}

pub fn break_single_byte_xor(bytes: &[u8]) -> (u8, Vec<u8>) {
    let mut min = (Vec::new(), 0, f32::INFINITY);

    for ascii_char in 32..126 {
        let xored: Vec<u8> = bytes.iter()
            .map(|byte| byte ^ ascii_char)
            .collect();

        let result = score(&xored);

        if result < min.2 {
            min = (xored, ascii_char, result);
        }
    }

    (min.1, min.0)
}

#[test]
fn test_break_single_byte_xor() {
    const INPUT: &'static str =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let ciphertext = hex::decode(INPUT).unwrap();
    let message = break_single_byte_xor(&ciphertext).1;
    let output = String::from_utf8(message).unwrap();
    assert_eq!(output, "Cooking MC's like a pound of bacon");
}

