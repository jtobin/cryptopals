
extern crate hex;

use std::error;
use std::fmt;
// use std::process;
use std::result;
// use std::string;

pub type Possibly<T> = result::Result<T, CPError>;

pub enum CPError {
    HexConversion(hex::FromHexError),
//    Utf8Conversion(string::FromUtf8Error)
}

impl fmt::Display for CPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CPError::HexConversion(ref err) =>
                fmt::Display::fmt(err, f),

//            CPError::Utf8Conversion(ref err) =>
//                fmt::Display::fmt(err, f)
        }
    }
}

impl error::Error for CPError {
    fn description(&self) -> &str {
        match *self {
            CPError::HexConversion(ref err) => err.description(),
//            CPError::Utf8Conversion(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CPError::HexConversion(ref err) => Some(err),
//            CPError::Utf8Conversion(ref err) => Some(err)
        }
    }
}

impl fmt::Debug for CPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CPError::HexConversion(ref err) =>
                fmt::Debug::fmt(err, f),

//            CPError::Utf8Conversion(ref err) =>
//                fmt::Debug::fmt(err, f)
        }
    }
}

// pub fn handle<A>(input: Result<A, CPError>) -> A {
//     input.unwrap_or_else(|err| {
//             println!("cryptopals (error):\n {}", err);
//             process::exit(1);
//     })
// }
