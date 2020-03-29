
extern crate colored;
extern crate goblin;
extern crate ignore;
extern crate serde_json;

use goblin::error::Error;
use goblin::mach::{Mach, MachO};
use goblin::Object;
use ignore::Walk;
use memmap::Mmap;
use serde_json::json;

use std::ffi::OsString;
use std::path::Path;
use std::{env, fs, io, process};

mod binary;

use binary::{BinSpecificProperties, BinType, Binaries, Binary};
use checksec::elf::ElfCheckSecResults;
use checksec::macho::MachOCheckSecResults;
use checksec::pe::PECheckSecResults;

fn parse(file: &Path) -> Result<Binary, Error> {
    let fp = fs::File::open(file);
    if let Err(err) = fp {
        return Err(Error::IO(err));
    }
    let buffer = unsafe { Mmap::map(&fp.unwrap()) };
    if let Ok(buffer) = buffer {
        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let results: ElfCheckSecResults =
                    ElfCheckSecResults::parse(&elf);
                let bin_type =
                    if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
                return Ok(Binary {
                    binarytype: bin_type,
                    file: file.display().to_string(),
                    properties: BinSpecificProperties::Elf(results),
                });
            }
            Object::PE(pe) => {
                let results = PECheckSecResults::parse(&pe, &buffer);
                let bin_type =
                    if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
                return Ok(Binary {
                    binarytype: bin_type,
                    file: file.display().to_string(),
                    properties: BinSpecificProperties::PE(results),
                });
            }
            Object::Mach(mach) => match mach {
                Mach::Binary(macho) => {
                    let results = MachOCheckSecResults::parse(&macho);
                    let bin_type = if macho.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    return Ok(Binary {
                        binarytype: bin_type,
                        file: file.display().to_string(),
                        properties: BinSpecificProperties::MachO(results),
                    });
                }
                Mach::Fat(fatmach) => {
                    for (idx, _) in fatmach.iter_arches().enumerate() {
                        let container: MachO = fatmach.get(idx).unwrap();
                        // TODO: change `parse()` to return Vec<Binary>
                        // for now only grab the result from the 64-bit object
                        // from a given Fat Mach-O binary
                        if container.is_64 {
                            let results =
                                MachOCheckSecResults::parse(&container);
                            let bin_type = BinType::MachO64;
                            return Ok(Binary {
                                binarytype: bin_type,
                                file: file.display().to_string(),
                                properties: BinSpecificProperties::MachO(
                                    results,
                                ),
                            });
                        }
                    }
                    return Err(Error::BadMagic(0));
                }
            },
            _ => return Err(Error::BadMagic(0)),
        }
    }
    Err(Error::IO(io::Error::last_os_error()))
}

fn walk(basepath: &Path, json: bool) {
    let mut bins = Vec::new();
    for result in Walk::new(basepath) {
        if let Ok(entry) = result {
            if let Some(filetype) = entry.file_type() {
                if filetype.is_file() {
                    if let Ok(result) = parse(entry.path()) {
                        if json {
                            bins.push(result);
                        } else {
                            println!("{}", result);
                        }
                    }
                }
            }
        }
    }
    if json {
        println!("{}", &json!(Binaries { binaries: bins }));
    }
}

fn usage() {
    println!("Usage: checksec <-f|-d> <file|directory> [--json]");
    process::exit(0);
}

fn main() {
    let argv: Vec<OsString> = env::args_os().collect();
    match argv.len() {
        3..=4 => {
            let json = argv.len() == 4 && argv[3] == "--json";
            if let Some(opt) = argv[1].to_str() {
                match opt {
                    "-d" => walk(Path::new(&argv[2]), json),
                    "-f" => {
                        if let Ok(results) = parse(Path::new(&argv[2])) {
                            if json {
                                println!(
                                    "{}",
                                    &json!(Binaries {
                                        binaries: vec![results]
                                    })
                                );
                            } else {
                                println!("{}", results);
                            }
                        }
                    }
                    _ => usage(),
                }
            }
        }
        _ => usage(),
    }
}
