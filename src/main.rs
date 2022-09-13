#![warn(clippy::pedantic)]
extern crate clap;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{
    crate_authors, crate_description, crate_version, Arg, ArgGroup, Command,
};
use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::Mach;
use goblin::Object;
use ignore::Walk;
use memmap::Mmap;
use serde_json::{json, to_string_pretty};
use sysinfo::{
    PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt,
};

use std::path::{Path, PathBuf};
use std::{env, fs, io, process};

#[cfg(feature = "color")]
use colored::Colorize;
#[cfg(feature = "color")]
use colored_json::to_colored_json_auto;

mod binary;
mod proc;

use binary::{BinSpecificProperties, BinType, Binaries, Binary};
use proc::{Process, Processes};

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(feature = "macho")]
use checksec::macho;
use checksec::output;
#[cfg(feature = "pe")]
use checksec::pe;
use checksec::underline;

fn print_binary_results(binaries: &Binaries, settings: &output::Settings) {
    match settings.format {
        output::Format::Json => {
            println!("{}", &json!(binaries));
        }
        output::Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(binaries))
                {
                    println!("{}", colored_json);
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{}", json_str);
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{}", json_str);
            }
        }
        output::Format::Text => {
            for binary in &binaries.binaries {
                println!("{}", binary);
            }
        }
    }
}

fn print_process_results(processes: &Processes, settings: &output::Settings) {
    match settings.format {
        output::Format::Json => {
            println!("{}", &json!(processes));
        }
        output::Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(processes))
                {
                    println!("{}", colored_json);
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{}", json_str);
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{}", json_str);
            }
        }
        output::Format::Text => {
            for process in &processes.processes {
                for binary in &process.binary {
                    if let Some(file_name) =
                        PathBuf::from(&binary.file).file_name()
                    {
                        if let Some(name) = file_name.to_str() {
                            println!(
                                "{}({})\n \u{21aa} {}",
                                name, process.pid, binary
                            );
                        }
                    }
                }
                #[cfg(all(
                    feature = "maps",
                    any(target_os = "linux", target_os = "windows")
                ))]
                if settings.maps {
                    if let Some(maps) = &process.maps {
                        println!("{:>12}", "\u{21aa} Maps:");
                        for map in maps {
                            println!("\t{}", map);
                        }
                    }
                }
            }
        }
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
                    match fatmach.arches() {
                        Ok(arches) => {
                            for (idx, _) in arches.iter().enumerate() {
                                if let Ok(container) = fatmach.get(idx) {
                                    let results =
                                        macho::CheckSecResults::parse(
                                            &container,
                                        );
                                    let bin_type = if container.is_64 {
                                        BinType::MachO64
                                    } else {
                                        BinType::MachO32
                                    };
                                    fat_bins.push(Binary::new(
                                        bin_type,
                                        file.display().to_string(),
                                        BinSpecificProperties::MachO(results),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                    return Ok(fat_bins);
                }
            },
            _ => return Err(Error::BadMagic(0)),
        }
    }
    Err(Error::IO(io::Error::last_os_error()))
}

fn walk(basepath: &Path, settings: &output::Settings) {
    let mut bins: Vec<Binary> = Vec::new();
    for result in Walk::new(basepath).flatten() {
        if let Some(filetype) = result.file_type() {
            if filetype.is_file() {
                if let Ok(mut result) = parse(result.path()) {
                    bins.append(&mut result);
                }
            }
        }
    }
    print_binary_results(&Binaries::new(bins), settings);
}
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
fn main() {
    let args = Command::new("checksec")
        .about(crate_description!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg_required_else_help(true)
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIRECTORY")
                .help("Target directory")
                .takes_value(true),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("Target file")
                .takes_value(true),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output in json format"),
        )
        .arg(
            Arg::new("maps")
                .short('m')
                .long("maps")
                .help("Include process memory maps (Linux only)")
                .requires("pid")
                .requires("process")
                .requires("process-all")
                .conflicts_with_all(&["directory", "file"]),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disables color output"),
        )
        .arg(
            Arg::new("pid")
                .long("pid")
                .value_name("PID")
                .help(
                    "Process ID of running process to check\n\
                    (comma separated for multiple PIDs)",
                )
                .takes_value(true),
        )
        .arg(
            Arg::new("pretty")
                .long("pretty")
                .help("Human readable json output")
                .requires("json"),
        )
        .arg(
            Arg::new("process")
                .short('p')
                .long("process")
                .value_name("NAME")
                .help("Name of running process to check")
                .takes_value(true),
        )
        .arg(
            Arg::new("process-all")
                .short('P')
                .long("process-all")
                .help("Check all running processes"),
        )
        .group(
            ArgGroup::new("operation")
                .args(&["directory", "file", "pid", "process", "process-all"])
                .required(true),
        )
        .get_matches();

    let file = args.value_of("file");
    let directory = args.value_of("directory");
    let procids = args.value_of("pid");
    let procname = args.value_of("process");
    let procall = args.is_present("process-all");

    let mut format = output::Format::Text;
    if args.is_present("json") {
        format = output::Format::Json;
        if args.is_present("pretty") {
            format = output::Format::JsonPretty;
        }
    }

    let settings = output::Settings::set(
        #[cfg(feature = "color")]
        !args.is_present("no-color"),
        format,
        args.is_present("maps"),
    );

    if procall {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );
        let mut procs: Vec<Process> = Vec::new();
        for (pid, proc_entry) in system.processes() {
            if let Ok(results) = parse(proc_entry.exe()) {
                procs.push(Process::new(pid.as_u32() as usize, results));
            }
        }
        print_process_results(&Processes::new(procs), &settings);
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
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );

        let mut procs: Vec<Process> = Vec::new();
        for procid in procids {
            let process = if let Some(process) = system.process(procid) {
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
                    procs
                        .push(Process::new(procid.as_u32() as usize, results));
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
        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(procname) = procname {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );
        let sysprocs = system.processes_by_name(procname);
        let mut procs: Vec<Process> = Vec::new();
        for proc_entry in sysprocs {
            if let Ok(results) = parse(proc_entry.exe()) {
                procs.push(Process::new(
                    proc_entry.pid().as_u32() as usize,
                    results,
                ));
            }
        }
        if procs.is_empty() {
            eprintln!("No process found matching name {}", procname);
            process::exit(1);
        }
        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(directory) = directory {
        let directory_path = Path::new(directory);

        if !directory_path.is_dir() {
            eprintln!("Directory {} not found", underline!(directory));
            process::exit(1);
        }

        walk(directory_path, &settings);
    } else if let Some(file) = file {
        let file_path = Path::new(file);

        if !file_path.is_file() {
            eprintln!("File {} not found", underline!(file));
            process::exit(1);
        }

        match parse(file_path) {
            Ok(results) => {
                print_binary_results(&Binaries::new(results), &settings);
            }
            Err(msg) => {
                eprintln!(
                    "Cannot parse binary file {}: {}",
                    underline!(file),
                    msg
                );
                process::exit(1);
            }
        }
    }
}
