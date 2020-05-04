extern crate clap;
extern crate goblin;
extern crate ignore;
extern crate serde_json;

use clap::{crate_authors, crate_description, crate_version, App, Arg};
use goblin::error::Error;
use goblin::mach::{Mach, MachO};
use goblin::Object;
use ignore::Walk;
use memmap::Mmap;
use serde_json::json;

use std::path::Path;
use std::{env, fs, io, process};

mod binary;

use binary::{BinSpecificProperties, BinType, Binaries, Binary};
use checksec::elf::ElfCheckSecResults;
use checksec::macho::MachOCheckSecResults;
use checksec::pe::PECheckSecResults;

fn parse(file: &Path) -> Result<Vec<Binary>, Error> {
    let fp = fs::File::open(file);
    if let Err(err) = fp {
        return Err(Error::IO(err));
    }
    if let Ok(buffer) = unsafe { Mmap::map(&fp.unwrap()) } {
        match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let results: ElfCheckSecResults =
                    ElfCheckSecResults::parse(&elf);
                let bin_type =
                    if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
                return Ok(vec![Binary {
                    binarytype: bin_type,
                    file: file.display().to_string(),
                    properties: BinSpecificProperties::Elf(results),
                }]);
            }
            Object::PE(pe) => {
                let results = PECheckSecResults::parse(&pe, &buffer);
                let bin_type =
                    if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
                return Ok(vec![Binary {
                    binarytype: bin_type,
                    file: file.display().to_string(),
                    properties: BinSpecificProperties::PE(results),
                }]);
            }
            Object::Mach(mach) => match mach {
                Mach::Binary(macho) => {
                    let results = MachOCheckSecResults::parse(&macho);
                    let bin_type = if macho.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    return Ok(vec![Binary {
                        binarytype: bin_type,
                        file: file.display().to_string(),
                        properties: BinSpecificProperties::MachO(results),
                    }]);
                }
                Mach::Fat(fatmach) => {
                    let mut fat_bins: Vec<Binary> = Vec::new();
                    for (idx, _) in fatmach.iter_arches().enumerate() {
                        let container: MachO = fatmach.get(idx).unwrap();
                        let results = MachOCheckSecResults::parse(&container);
                        let bin_type = if container.is_64 {
                            BinType::MachO64
                        } else {
                            BinType::MachO32
                        };
                        fat_bins.append(&mut vec![Binary {
                            binarytype: bin_type,
                            file: file.display().to_string(),
                            properties: BinSpecificProperties::MachO(results),
                        }]);
                    }
                    return Ok(fat_bins);
                }
            },
            _ => return Err(Error::BadMagic(0)),
        }
    }
    Err(Error::IO(io::Error::last_os_error()))
}

fn walk(basepath: &Path, json: bool) {
    let mut bins: Vec<Binary> = Vec::new();
    for result in Walk::new(basepath) {
        if let Ok(entry) = result {
            if let Some(filetype) = entry.file_type() {
                if filetype.is_file() {
                    if let Ok(mut result) = parse(entry.path()) {
                        if json {
                            bins.append(&mut result);
                        } else {
                            for bin in result.iter() {
                                println!("{}", bin);
                            }
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

fn main() {
    let args = App::new("checksec")
        .about(crate_description!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Target file")
                .takes_value(true)
                .conflicts_with("directory"),
        )
        .arg(
            Arg::with_name("directory")
                .short("d")
                .long("directory")
                .value_name("DIRECTORY")
                .help("Target directory")
                .takes_value(true)
                .conflicts_with("file"),
        )
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Output in json format"),
        )
        .get_matches();

    let json = args.is_present("json");
    let arg_file = args.value_of("file");
    let arg_directory = args.value_of("directory");

    // make sure a file or a directory is supplied
    if arg_file.is_none() && arg_directory.is_none() {
        println!("{}", args.usage());
        process::exit(0);
    }
    if let Some(directory) = arg_directory {
        walk(Path::new(&directory), json);
    } else if let Some(file) = arg_file {
        if let Ok(results) = parse(Path::new(&file)) {
            if json {
                println!("{}", &json!(Binaries { binaries: results }));
            } else {
                for result in results.iter() {
                    println!("{}", result);
                }
            }
        }
    }
}
