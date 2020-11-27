extern crate checksec;
extern crate goblin;

use checksec::macho::CheckSecResults;
use goblin::mach::{Mach, MachO};
use goblin::Object;
use std::{env, fs};

fn main() {
    let argv: Vec<String> = env::args().collect();
    match argv.len() {
        2 => {
            if fs::File::open(&argv[1]).is_ok() {
                if let Ok(buf) = fs::read(&argv[1]) {
                    match Object::parse(&buf).unwrap() {
                        Object::Mach(mach) => match mach {
                            Mach::Binary(macho) => {
                                println!(
                                    "{:#?}",
                                    CheckSecResults::parse(&macho)
                                );
                            }
                            Mach::Fat(fatmach) => {
                                for (idx, _) in
                                    fatmach.iter_arches().enumerate()
                                {
                                    let container: MachO =
                                        fatmach.get(idx).unwrap();
                                    println!(
                                        "{:#?}",
                                        CheckSecResults::parse(&container)
                                    );
                                }
                            }
                        },
                        _ => eprintln!("not a mach binary"),
                    }
                }
            }
        }
        _ => eprintln!("Usage: macho_print_checksec_results <binary>"),
    }
}
