
extern crate hex;

use std::error;
use std::fmt;
use std::process;

pub enum CryptopalsError {
    HexConversionError(hex::FromHexError)
}

impl fmt::Display for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptopalsError::HexConversionError(ref err) =>
                fmt::Display::fmt(err, f)
        }
    }
}

impl error::Error for CryptopalsError {
    fn description(&self) -> &str {
        match *self {
            CryptopalsError::HexConversionError(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CryptopalsError::HexConversionError(ref err) => Some(err)
        }
    }
}

impl fmt::Debug for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptopalsError::HexConversionError(ref err) =>
                fmt::Debug::fmt(err, f)
        }
    }
}

pub fn handle<A>(input: Result<A, CryptopalsError>) -> A {
    input.unwrap_or_else(|err| {
            println!("error (cryptopals):\n {}", err);
            process::exit(1);
    })
}
