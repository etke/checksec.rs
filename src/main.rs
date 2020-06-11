extern crate clap;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{crate_authors, crate_description, crate_version, App, Arg};
use goblin::error::Error;
use goblin::mach::{Mach, MachO};
use goblin::Object;
use ignore::Walk;
use memmap::Mmap;
use serde_json::json;
use sysinfo::{ProcessExt, System, SystemExt};

use std::path::Path;
use std::{env, fs, io, process};

mod binary;

use binary::{
    BinSpecificProperties, BinType, Binaries, Binary, Process, Processes,
};
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
                return Ok(vec![Binary::new(
                    bin_type,
                    file.display().to_string(),
                    BinSpecificProperties::Elf(results),
                )]);
            }
            Object::PE(pe) => {
                let results = PECheckSecResults::parse(&pe, &buffer);
                let bin_type =
                    if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
                return Ok(vec![Binary::new(
                    bin_type,
                    file.display().to_string(),
                    BinSpecificProperties::PE(results),
                )]);
            }
            Object::Mach(mach) => match mach {
                Mach::Binary(macho) => {
                    let results = MachOCheckSecResults::parse(&macho);
                    let bin_type = if macho.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    return Ok(vec![Binary::new(
                        bin_type,
                        file.display().to_string(),
                        BinSpecificProperties::MachO(results),
                    )]);
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
                        fat_bins.append(&mut vec![Binary::new(
                            bin_type,
                            file.display().to_string(),
                            BinSpecificProperties::MachO(results),
                        )]);
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
        println!("{}", &json!(Binaries::new(bins)));
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
                .conflicts_with("directory")
                .conflicts_with("process")
                .conflicts_with("process-all"),
        )
        .arg(
            Arg::with_name("directory")
                .short("d")
                .long("directory")
                .value_name("DIRECTORY")
                .help("Target directory")
                .takes_value(true)
                .conflicts_with("file")
                .conflicts_with("process")
                .conflicts_with("process-all"),
        )
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Output in json format"),
        )
        .arg(
            Arg::with_name("process")
                .short("p")
                .long("process")
                .value_name("NAME")
                .help("Name of running process to check")
                .takes_value(true)
                .conflicts_with("directory")
                .conflicts_with("file")
                .conflicts_with("process-all"),
        )
        .arg(
            Arg::with_name("process-all")
                .short("P")
                .long("process-all")
                .help("Check all running processes")
                .conflicts_with("directory")
                .conflicts_with("file")
                .conflicts_with("process"),
        )
        .get_matches();

    let json = args.is_present("json");
    let file = args.value_of("file");
    let directory = args.value_of("directory");
    let procname = args.value_of("process");
    let procall = args.is_present("process-all");

    // make sure a file or a directory is supplied
    if !procall && file.is_none() && directory.is_none() && procname.is_none()
    {
        println!("{}", args.usage());
        process::exit(0);
    }

    if procall {
        let system: System = System::new_all();
        let mut procs: Vec<Process> = Vec::new();
        for (pid, proc_entry) in system.get_processes() {
            if let Ok(results) = parse(proc_entry.exe()) {
                if json {
                    procs.append(&mut vec![Process::new(
                        *pid as usize,
                        results,
                    )])
                } else {
                    for result in results.iter() {
                        println!(
                            "{}({})\n ↪ {}",
                            proc_entry.name(),
                            pid,
                            result
                        );
                    }
                }
            }
        }
        if json {
            println!("{}", &json!(Processes::new(procs)));
        }
    } else if let Some(procname) = procname {
        let system: System = System::new_all();
        let mut procs: Vec<Process> = Vec::new();
        for proc_entry in system.get_process_by_name(procname) {
            if let Ok(results) = parse(&proc_entry.exe()) {
                if json {
                    procs.append(&mut vec![Process::new(
                        proc_entry.pid() as usize,
                        results,
                    )])
                } else {
                    for result in results.iter() {
                        println!(
                            "{}({})\n ↪ {}",
                            proc_entry.name(),
                            proc_entry.pid(),
                            result
                        );
                    }
                }
            }
        }
        if json {
            println!("{}", &json!(Processes::new(procs)));
        }
    } else if let Some(directory) = directory {
        walk(Path::new(&directory), json);
    } else if let Some(file) = file {
        if let Ok(results) = parse(Path::new(&file)) {
            if json {
                println!("{}", &json!(Binaries::new(results)));
            } else {
                for result in results.iter() {
                    println!("{}", result);
                }
            }
        }
    }
}
