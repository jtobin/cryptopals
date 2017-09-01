
mod s1c01;
mod s1c02;
mod s1c03;
mod s1c07;

mod s2c09;
mod s2c10;
mod s2c11;
mod s2c12;

mod errors;

fn main() {
    println!("s1c01:\n{}\n", errors::handle(s1c01::s1c01()));
    println!("s1c02:\n{}\n", s1c02::s1c02());
    println!("s1c03:\n{}\n", s1c03::s1c03());
    println!("s1c07:\n{}\n", s1c07::s1c07());
    println!("s2c09:\n{}\n", s2c09::s2c09());
    println!("s2c10:\n{}\n", s2c10::s2c10());
    println!("s2c11:\n{}\n", s2c11::s2c11());
    println!("s2c12:\n{}\n", s2c12::s2c12());
}
