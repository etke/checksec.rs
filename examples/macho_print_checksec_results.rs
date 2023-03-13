extern crate checksec;
extern crate goblin;

use checksec::macho::CheckSecResults;
use goblin::mach::cputype::get_arch_name_from_types;
use goblin::mach::Mach;
use goblin::mach::SingleArch::Archive;
use goblin::mach::SingleArch::MachO;
use goblin::Object;
use std::{env, fs};

fn main() {
    let argv: Vec<String> = env::args().collect();
    match argv.len() {
        2 => {
            if fs::File::open(&argv[1]).is_ok() {
                if let Ok(buf) = fs::read(&argv[1]) {
                    parse(&buf);
                }
            }
        }
        _ => eprintln!("Usage: macho_print_checksec_results <binary>"),
    }
}

fn parse(bytes: &[u8]) {
    match Object::parse(bytes).unwrap() {
        Object::Mach(mach) => match mach {
            Mach::Binary(macho) => {
                println!("{:#?}", CheckSecResults::parse(&macho));
            }
            Mach::Fat(fatmach) => {
                for (idx, fatarch) in fatmach.iter_arches().enumerate() {
                    match fatmach.get(idx).unwrap() {
                        MachO(mach) => {
                            let machine = get_arch_name_from_types(
                                mach.header.cputype(),
                                mach.header.cpusubtype(),
                            )
                            .unwrap_or("UNKNOWN");
                            println!("# Machine type {}:", machine);
                            println!("{:#?}", CheckSecResults::parse(&mach))
                        }
                        Archive(archive) => {
                            let fatarch = fatarch.unwrap();

                            let archive_bytes = &bytes[fatarch.offset as usize
                                ..(fatarch.offset + fatarch.size) as usize];

                            for member in archive.members() {
                                match archive.extract(member, archive_bytes) {
                                    Ok(ext_bytes) => {
                                        println!(
                                            "# Archive member {}:",
                                            member
                                        );
                                        parse(ext_bytes);
                                    }
                                    Err(err) => {
                                        eprintln!(
                                            "Failed to extract member {}: {}",
                                            member, err
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        _ => eprintln!("not a mach binary"),
    }
}
