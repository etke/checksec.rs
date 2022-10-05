extern crate checksec;
extern crate goblin;

use checksec::elf::CheckSecResults;
use goblin::Object;
use std::{env, fs};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() == 2 {
        if fs::File::open(&argv[1]).is_ok() {
            if let Ok(buf) = fs::read(&argv[1]) {
                match Object::parse(&buf).unwrap() {
                    Object::Elf(elf) => {
                        println!("{:#?}", CheckSecResults::parse(&elf, &buf))
                    }
                    _ => println!("Not an elf binary."),
                }
            }
        }
    } else {
        eprintln!("Usage: elf_print_checksec_results <binary>");
    }
}
