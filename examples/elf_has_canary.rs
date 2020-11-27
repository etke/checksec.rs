extern crate checksec;
extern crate goblin;

use checksec::elf::Properties;
use goblin::elf::Elf;
use std::{env, fs, path::Path};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() == 2 {
        if fs::File::open(&argv[1]).is_ok() {
            if let Ok(buf) = fs::read(Path::new(&argv[1])) {
                if let Ok(elf) = Elf::parse(&buf) {
                    println!("Canary: {}", elf.has_canary());
                }
            }
        }
    } else {
        eprintln!("Usage: read_elf_canary <binary>");
    }
}
