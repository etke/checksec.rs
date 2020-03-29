extern crate checksec;
extern crate goblin;

use checksec::elf::ElfProperties;
use goblin::Object;
use std::ffi::OsString;
use std::{env, fs, path::Path};

fn main() {
    let argv: Vec<OsString> = env::args_os().collect();
    match argv.len() {
        2 => {
            if fs::File::open(&argv[1]).is_ok() {
                if let Ok(buf) = fs::read(Path::new(&argv[1])) {
                    match Object::parse(&buf).unwrap() {
                        Object::Elf(elf) => {
                            println!("Canary: {}", elf.has_canary())
                        }
                        _ => println!("Not an elf binary."),
                    }
                }
            }
        }
        _ => println!("Usage: elf_has_canary <binary>"),
    }
}
