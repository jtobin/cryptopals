# cryptopals

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jtobin/cryptopals/blob/master/LICENSE)

Matasano's [cryptopals challenges](http://cryptopals.com/), implemented mainly
in [Rust](https://www.rust-lang.org) and [Haskell](https://haskell-lang.org/).

## Problems

To check some of these you can use the following general pattern:

    $ SOLUTION = $(whatever)
    $ diff <(echo $SOLUTION) /path/to/golden/output

This is illustrated for 1.1.

### Set 1

#### 1.1

    $ SOLUTION=$(cat data/s1/q1_input.txt | ./bin/hex2b64)
    $ diff <(echo $SOLUTION) data/s1/q1_output.txt

#### 1.2

    $ ./bin/fixed_xor $(< data/s1/q2_input.txt) $(< data/s1/q2_against.txt)
    746865206b696420646f6e277420706c6179

#### 1.3

    $ ./bin/charfreq $(cat data/s1/q3_input.txt)
    original: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    byte (frequency)
    ----------------
    120 (6)
    55 (5)
    54 (3)
    49 (2)
    27 (2)

    $ cat data/s1/q3_input.txt | ./bin/single_byte_xor 120
    original: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

    xored with: 120 (x)
    decrypted: cOOKINGmcSLIKEAPOUNDOFBACON

#### 1.4

    $ parallel -a data/s1/q4_input.txt ./bin/charfreq | less
    $ # look for strings w/high-frequency bytes
    $ INPUT=7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
    $ HIGH_FREQ_BYTE=21
    $ echo $INPUT | ./bin/single_byte_xor $HIGH_FREQ_BYTE
    original: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f

    xored with: 21 ()
    decrypted: nOWTHATTHEPARTYISJUMPING*

#### 1.5

    $ echo -n $(cat data/s1/q5_input.txt) | ./bin/repeating_key_xor ICE | fold -w 74
    original:
    Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal
    xored with: ICE
    result:
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527
    2a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f


#### 1.6

    $ INPUT=$(cat data/s1/q6_input.txt | ./bin/b642hex)

