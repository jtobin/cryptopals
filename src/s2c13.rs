
extern crate combine;

use self::combine::{many1, sep_by, token, none_of};
// use self::combine::char::letter;

pub fn foo(input: String) -> String {
    let metachars = "&=".iter().cloned();
    let word      = many1(none_of(metachars));
    let pair      = sep_by(word, token('='));
    let pairs     = sep_by(pair, token('&'));

    String::from("hello")
}


pub fn s2c13() -> String{
    String::from("foo")
}



// pub fn s2c13() -> String {
//     // FIXME & is not right here - there shouldn't be a hanging &
//     let structured_cookie = Regex::new(r"([A-Za-z]+=[^&=]*&?)*").unwrap();
//
//     let test = structured_cookie.captures("foo=bar&baz=quux").unwrap();
//
//     println!("{} {}", test.get(0).unwrap().as_str(), test.get(1).unwrap().as_str());
//
//     String::from("foo")
// }

//
// foo=bar&baz=qux
//
// parse that into some kind of json
//
// {
//   'foo': 'bar',
//   'baz': 'qux'
// }
//
