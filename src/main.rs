extern crate clap;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{crate_authors, crate_description, crate_version, App, Arg};
use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::{Mach, MachO};
use goblin::Object;
use ignore::Walk;
use memmap::Mmap;
#[cfg(not(feature = "color"))]
use serde_json::to_string_pretty;
use serde_json::{json, Value};
use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use std::path::Path;
use std::{env, fs, io, process};

#[cfg(feature = "color")]
use colored::Colorize;
#[cfg(feature = "color")]
use colored_json::to_colored_json_auto;

mod binary;

use binary::{
    BinSpecificProperties, BinType, Binaries, Binary, Process, Processes,
};
#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(feature = "macho")]
use checksec::macho;
#[cfg(feature = "pe")]
use checksec::pe;
use checksec::underline;

fn json_print(data: &Value, pretty: bool) {
    if pretty {
        #[cfg(feature = "color")]
        if let Ok(colored_json) = to_colored_json_auto(data) {
            println!("{}", colored_json);
        }
        #[cfg(not(feature = "color"))]
        if let Ok(json_str) = to_string_pretty(data) {
            println!("{}", json_str);
        }
    } else {
        println!("{}", data);
    }
}

fn parse(file: &Path) -> Result<Vec<Binary>, Error> {
    let fp = fs::File::open(file);
    if let Err(err) = fp {
        return Err(Error::IO(err));
    }
    if let Ok(buffer) = unsafe { Mmap::map(&fp.unwrap()) } {
        match Object::parse(&buffer)? {
            #[cfg(feature = "elf")]
            Object::Elf(elf) => {
                let results = elf::CheckSecResults::parse(&elf);
                let bin_type =
                    if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
                return Ok(vec![Binary::new(
                    bin_type,
                    file.display().to_string(),
                    BinSpecificProperties::Elf(results),
                )]);
            }
            #[cfg(feature = "pe")]
            Object::PE(pe) => {
                let results = pe::CheckSecResults::parse(&pe, &buffer);
                let bin_type =
                    if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
                return Ok(vec![Binary::new(
                    bin_type,
                    file.display().to_string(),
                    BinSpecificProperties::PE(results),
                )]);
            }
            #[cfg(feature = "macho")]
            Object::Mach(mach) => match mach {
                Mach::Binary(macho) => {
                    let results = macho::CheckSecResults::parse(&macho);
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
                        let results =
                            macho::CheckSecResults::parse(&container);
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

fn walk(basepath: &Path, json: bool, pretty: bool) {
    let mut bins: Vec<Binary> = Vec::new();
    for result in Walk::new(basepath).flatten() {
        if let Some(filetype) = result.file_type() {
            if filetype.is_file() {
                if let Ok(mut result) = parse(result.path()) {
                    if json {
                        bins.append(&mut result);
                    } else {
                        for bin in &result {
                            println!("{}", bin);
                        }
                    }
                }
            }
        }
    }
    if json {
        json_print(&json!(Binaries::new(bins)), pretty);
    }
}
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
                .conflicts_with("pid")
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
                .conflicts_with("pid")
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
            Arg::with_name("pretty")
                .long("pretty")
                .help("Human readable json output")
                .requires("json"),
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
                .conflicts_with("pid")
                .conflicts_with("process-all"),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .value_name("PID")
                .help(
                    "Process ID of running process to check [multiple IDs
                       can be specified separated by a comma]",
                )
                .takes_value(true)
                .conflicts_with("directory")
                .conflicts_with("file")
                .conflicts_with("process")
                .conflicts_with("process-all"),
        )
        .arg(
            Arg::with_name("process-all")
                .short("P")
                .long("process-all")
                .help("Check all running processes")
                .conflicts_with("directory")
                .conflicts_with("file")
                .conflicts_with("pid")
                .conflicts_with("process"),
        )
        .get_matches();

    let json = args.is_present("json");
    let file = args.value_of("file");
    let directory = args.value_of("directory");
    let pretty = args.is_present("pretty");
    let procids = args.value_of("pid");
    let procname = args.value_of("process");
    let procall = args.is_present("process-all");

    if procall {
        let system =
            System::new_with_specifics(RefreshKind::new().with_processes());
        let mut procs: Vec<Process> = Vec::new();
        for (pid, proc_entry) in system.get_processes() {
            if let Ok(results) = parse(proc_entry.exe()) {
                if json {
                    #[allow(clippy::cast_sign_loss)]
                    procs.append(&mut vec![Process::new(
                        *pid as usize,
                        results,
                    )]);
                } else {
                    for result in &results {
                        println!(
                            "{}({})\n \u{21aa} {}",
                            proc_entry.name(),
                            pid,
                            result
                        );
                    }
                }
            }
        }
        if json {
            json_print(&json!(Processes::new(procs)), pretty);
        }
    } else if let Some(procids) = procids {
        let procids: Vec<sysinfo::Pid> = procids
            .split(',')
            .map(|id| match id.parse::<sysinfo::Pid>() {
                Ok(id) => id,
                Err(msg) => {
                    eprintln!("Invalid process ID {}: {}", id, msg);
                    process::exit(1);
                }
            })
            .collect();
        let system =
            System::new_with_specifics(RefreshKind::new().with_processes());

        for procid in procids {
            let process = if let Some(process) = system.get_process(procid) {
                process
            } else {
                eprintln!("No process found with ID {}", procid);
                continue;
            };

            if !process.exe().is_file() {
                eprintln!(
                    "No valid executable found for process {} with ID {}: {}",
                    process.name(),
                    procid,
                    process.exe().display()
                );
                continue;
            }

            match parse(process.exe()) {
                Ok(results) => {
                    if json {
                        #[allow(clippy::cast_sign_loss)]
                        json_print(
                            &json!(Process::new(procid as usize, results)),
                            pretty,
                        );
                    } else {
                        for result in &results {
                            println!(
                                "{}({})\n \u{21aa} {}",
                                process.name(),
                                process.pid(),
                                result
                            );
                        }
                    }
                }
                Err(msg) => {
                    eprintln!(
                        "Can not parse process {} with ID {}: {}",
                        process.name(),
                        procid,
                        msg
                    );
                    continue;
                }
            }
        }
    } else if let Some(procname) = procname {
        let system =
            System::new_with_specifics(RefreshKind::new().with_processes());
        let sysprocs = system.get_process_by_name(procname);
        if sysprocs.is_empty() {
            eprintln!("No process found matching name {}", procname);
            process::exit(1);
        }
        let mut procs: Vec<Process> = Vec::new();
        for proc_entry in &sysprocs {
            if let Ok(results) = parse(proc_entry.exe()) {
                if json {
                    #[allow(clippy::cast_sign_loss)]
                    procs.append(&mut vec![Process::new(
                        proc_entry.pid() as usize,
                        results,
                    )]);
                } else {
                    for result in &results {
                        println!(
                            "{}({})\n \u{21aa} {}",
                            proc_entry.name(),
                            proc_entry.pid(),
                            result
                        );
                    }
                }
            }
        }
        if json {
            json_print(&json!(Processes::new(procs)), pretty);
        }
    } else if let Some(directory) = directory {
        let directory_path = Path::new(directory);

        if !directory_path.is_dir() {
            eprintln!("Directory {} not found", underline!(directory));
            process::exit(1);
        }

        walk(directory_path, json, pretty);
    } else if let Some(file) = file {
        let file_path = Path::new(file);

        if !file_path.is_file() {
            eprintln!("File {} not found", underline!(file));
            process::exit(1);
        }

        match parse(file_path) {
            Ok(results) => {
                if json {
                    json_print(&json!(Binaries::new(results)), pretty);
                } else {
                    for result in &results {
                        println!("{}", result);
                    }
                }
            }
            Err(msg) => {
                eprintln!(
                    "Can not parse binary file {}: {}",
                    underline!(file),
                    msg
                );
                process::exit(1);
            }
        }
    } else {
        eprintln!("{}", args.usage());
        process::exit(1);
    }
}
