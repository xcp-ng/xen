use std::io::{Read, stdin};

pub mod abi;
pub mod c_lang;
pub mod spec;

fn main() {
    let mut buffer = String::new();
    stdin().read_to_string(&mut buffer).unwrap();

    let abi_spec: spec::AbiSpec = serde_yaml::from_str(&buffer).unwrap();

    let mut buffer = String::new();

    c_lang::generate_code(&mut buffer, abi_spec).unwrap();
    print!("{buffer}");
}
