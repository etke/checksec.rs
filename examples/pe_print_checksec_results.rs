extern crate checksec;
extern crate goblin;
extern crate memmap;

use checksec::pe::PECheckSecResults;
use goblin::Object;
use memmap::Mmap;
use std::{env, fs};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() == 2 {
        if let Ok(fp) = fs::File::open(&argv[1]) {
            if let Ok(buf) = unsafe { Mmap::map(&fp) } {
                if let Ok(obj) = Object::parse(&buf) {
                    match obj {
                        Object::PE(pe) => println!(
                            "{:#?}",
                            PECheckSecResults::parse(&pe, &buf)
                        ),
                        _ => println!("Not an pe binary."),
                    }
                }
            }
        }
    } else {
        println!("Usage: pe_print_checksec_results <binary>");
    }
}
