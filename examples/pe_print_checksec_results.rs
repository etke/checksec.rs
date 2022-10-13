extern crate checksec;
extern crate goblin;
extern crate memmap2;

use checksec::pe::CheckSecResults;
use goblin::Object;
use memmap2::Mmap;
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
                            CheckSecResults::parse(&pe, &buf)
                        ),
                        _ => println!("Not an pe binary."),
                    }
                }
            }
        }
    } else {
        eprintln!("Usage: pe_print_checksec_results <binary>");
    }
}
