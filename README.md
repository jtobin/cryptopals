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

One could write no code at all:

    $ xxd -r -p data/s1/q1_input.txt | base64

It's also fun to check the ASCII-encoded input:

    $ xxd -r -p data/s1/q1_input.txt
    I'm killing your brain like a poisonous mushroom

#### 1.2

    $ SOLUTION=$(./bin/fixed_xor $(< data/s1/q2_input.txt) $(< data/s1/q2_against.txt))
    746865206b696420646f6e277420706c6179

ASCII-encoded output is fun:

    $ echo $SOLUTION | xxd -r -p
    the kid don't play

#### 1.3

    $ ./bin/charfreq $(< data/s1/q3_input.txt)
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

Here it's worth noting that you can usually get a better decryption by using
the opposite case, so (ASCII-encoded +- 32):

    $ cat data/s1/q3_input.txt | ./bin/single_byte_xor 88
    original: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

    xored with: 88 (X)
    decrypted: Cooking MC's like a pound of bacon

#### 1.4

    $ parallel -a data/s1/q4_input.txt ./bin/charfreq | less

Look for strings w/high-frequency bytes and you'll find the following
w/five hits of ASCII-encoded 21.  There's another input in which ']' gets five
hits, but it doesn't seem to decrypt to anything.

    $ INPUT=7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
    $ HIGH_FREQ_BYTE=21
    $ echo $INPUT | ./bin/single_byte_xor $HIGH_FREQ_BYTE
    original: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f

    xored with: 21 ()
    decrypted: nOWTHATTHEPARTYISJUMPING*

Similar here, using 21 + 32:

    $ echo $INPUT | ./bin/single_byte_xor 53
    original: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f

    xored with: 53 (5)
    decrypted: Now that the party is jumping

#### 1.5

    $ echo -n $(< data/s1/q5_input.txt) | ./bin/repeating_key_xor ICE | fold -w 74
    original:
    Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal
    xored with: ICE
    result:
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527
    2a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Can check this by grabbing the result under 'INPUT' and xor-ing it again:

    $ xxd -r -p <<< $INPUT | ./bin/repeating_key_xor ICE | xxd -r -p | less

#### 1.6

    $ INPUTB64=$(< data/s1/q6_input.txt)
    $ INPUTHEX=$(echo $INPUTB64 | ./bin/b642hex)
    $ echo $INPUTB64 | ./bin/score_keysizes 4 10

Top keysizes for average of 4+ groups are roughly 5, 29, 3.

Five doesn't go far:

    $ KEYSIZE=5
    $ echo $INPUTHEX | ./bin/rotate $KEYSIZE | parallel -k ./bin/charfreq | less

Twenty-nine does it:

    $ KEYSIZE=29
    $ echo $INPUTHEX | ./bin/rotate $KEYSIZE | parallel -k ./bin/charfreq | less
    $ xxd -r -p <<< "$INPUTHEX" | \
        ./bin/repeating_key_xor "tERMINATOR x  bRING THE NOISE" | \
        xxd -r -p | less

Shift by 32 for readability:

    $ xxd -r -p <<< "$INPUTHEX" | \
        ./bin/repeating_key_xor "Terminator X: Bring the noise" | \
        xxd -r -p | less

