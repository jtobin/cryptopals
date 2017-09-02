
extern crate hex;

use std::error;
use std::fmt;
use std::process;
use std::string;

pub enum CryptopalsError {
    HexConversionError(hex::FromHexError),
    Utf8ConversionError(string::FromUtf8Error)
}

impl fmt::Display for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptopalsError::HexConversionError(ref err) =>
                fmt::Display::fmt(err, f),

            CryptopalsError::Utf8ConversionError(ref err) =>
                fmt::Display::fmt(err, f)
        }
    }
}

impl error::Error for CryptopalsError {
    fn description(&self) -> &str {
        match *self {
            CryptopalsError::HexConversionError(ref err) => err.description(),
            CryptopalsError::Utf8ConversionError(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CryptopalsError::HexConversionError(ref err) => Some(err),
            CryptopalsError::Utf8ConversionError(ref err) => Some(err)
        }
    }
}

impl fmt::Debug for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptopalsError::HexConversionError(ref err) =>
                fmt::Debug::fmt(err, f),

            CryptopalsError::Utf8ConversionError(ref err) =>
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
