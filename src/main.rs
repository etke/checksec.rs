#![warn(clippy::pedantic)]
extern crate clap;
extern crate core;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{
    crate_authors, crate_description, crate_version, Arg, ArgAction, ArgGroup,
    Command, ValueHint,
};
use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::Mach;
use goblin::Object;
use ignore::Walk;
use memmap2::Mmap;
use serde_json::{json, to_string_pretty};
use sysinfo::{
    PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt,
};

use std::ffi::OsStr;
use std::io::{self, BufRead};
use std::path::Path;
use std::{env, fmt, fs, process};

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
                    println!(
                        "{}({})\n \u{21aa} {}",
                        binary
                            .file
                            .file_name()
                            .unwrap_or_else(|| OsStr::new("n/a"))
                            .to_string_lossy(),
                        process.pid,
                        binary
                    );
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

enum ParseError {
    Goblin(goblin::error::Error),
    IO(std::io::Error),
    #[allow(dead_code)]
    Unimplemented(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Goblin(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            Self::Unimplemented(str) => {
                write!(f, "Support for files of type {} not implemented", str)
            }
        }
    }
}

impl From<goblin::error::Error> for ParseError {
    fn from(err: goblin::error::Error) -> ParseError {
        ParseError::Goblin(err)
    }
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IO(err)
    }
}

fn parse(file: &Path) -> Result<Vec<Binary>, ParseError> {
    let fp = fs::File::open(file)?;
    let buffer = unsafe { Mmap::map(&fp)? };

    parse_bytes(&buffer, file)
}

#[allow(clippy::too_many_lines)]
fn parse_bytes(bytes: &[u8], file: &Path) -> Result<Vec<Binary>, ParseError> {
    match Object::parse(bytes)? {
        #[cfg(feature = "elf")]
        Object::Elf(elf) => {
            let results = elf::CheckSecResults::parse(&elf);
            let bin_type =
                if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
            Ok(vec![Binary::new(
                bin_type,
                file.to_path_buf(),
                BinSpecificProperties::Elf(results),
            )])
        }
        #[cfg(feature = "pe")]
        Object::PE(pe) => {
            let results = pe::CheckSecResults::parse(&pe, bytes);
            let bin_type =
                if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
            Ok(vec![Binary::new(
                bin_type,
                file.to_path_buf(),
                BinSpecificProperties::PE(results),
            )])
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
                Ok(vec![Binary::new(
                    bin_type,
                    file.to_path_buf(),
                    BinSpecificProperties::MachO(results),
                )])
            }
            Mach::Fat(fatmach) => {
                let mut fat_bins: Vec<Binary> = Vec::new();
                for (idx, _) in fatmach.arches()?.iter().enumerate() {
                    if let Ok(container) = fatmach.get(idx) {
                        let results =
                            macho::CheckSecResults::parse(&container);
                        let bin_type = if container.is_64 {
                            BinType::MachO64
                        } else {
                            BinType::MachO32
                        };
                        fat_bins.push(Binary::new(
                            bin_type,
                            file.to_path_buf(),
                            BinSpecificProperties::MachO(results),
                        ));
                    }
                }
                Ok(fat_bins)
            }
        },
        #[cfg(not(feature = "elf"))]
        Object::Elf(_) => Err(ParseError::Unimplemented("ELF")),
        #[cfg(not(feature = "pe"))]
        Object::PE(_) => Err(ParseError::Unimplemented("PE")),
        #[cfg(not(feature = "macho"))]
        Object::Mach(_) => Err(ParseError::Unimplemented("MachO")),
        Object::Archive(archive) => Ok(archive
            .members()
            .iter()
            .filter_map(|member_name| {
                match archive.extract(member_name, bytes) {
                    Ok(ext_bytes) => parse_bytes(
                        ext_bytes,
                        Path::new(&format!(
                            "{}\u{2794}{}",
                            file.display(),
                            member_name
                        )),
                    )
                    .ok(),
                    Err(err) => {
                        eprintln!(
                            "Failed to extract member {} of {}: {}",
                            member_name,
                            file.display(),
                            err
                        );
                        None
                    }
                }
            })
            .flatten()
            .collect()),
        Object::Unknown(magic) => {
            Err(ParseError::Goblin(Error::BadMagic(magic)))
        }
    }
}

fn walk(basepath: &Path) -> Vec<Binary> {
    let mut bins = Vec::new();
    for result in Walk::new(basepath).flatten() {
        if let Some(filetype) = result.file_type() {
            if filetype.is_file() {
                if let Ok(mut result) = parse(result.path()) {
                    bins.append(&mut result);
                }
            }
        }
    }
    bins
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
                .action(clap::ArgAction::Append)
                .value_name("DIRECTORY")
                .value_hint(ValueHint::DirPath)
                .help("Target directory"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .action(clap::ArgAction::Append)
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help("Target file"),
        )
        .arg(
            Arg::new("file-list")
                .long("file-list")
                .value_name("FILELIST")
                .default_missing_value("<stdin>")
                .num_args(0..=1)
                .help("List of target files.  Read from standard input if no value specified."),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output in json format"),
        )
        .arg(
            Arg::new("maps")
                .short('m')
                .long("maps")
                .action(ArgAction::SetTrue)
                .help("Include process memory maps (linux only)")
                .requires("pid")
                .requires("process")
                .requires("process-all")
                .conflicts_with_all(&["directory", "file"]),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .help("Disables color output"),
        )
        .arg(
            Arg::new("pid")
                .help(
                    "Process ID of running process to check\n\
                    (comma separated for multiple PIDs)",
                )
                .long("pid")
                .value_name("PID"),
        )
        .arg(
            Arg::new("pretty")
                .long("pretty")
                .action(ArgAction::SetTrue)
                .help("Human readable json output")
                .requires("json"),
        )
        .arg(
            Arg::new("process")
                .short('p')
                .long("process")
                .action(clap::ArgAction::Append)
                .value_name("NAME")
                .help("Name of running process to check"),
        )
        .arg(
            Arg::new("process-all")
                .short('P')
                .long("process-all")
                .action(ArgAction::SetTrue)
                .help("Check all running processes"),
        )
        .group(
            ArgGroup::new("operation")
                .args(&[
                    "directory",
                    "file",
                    "file-list",
                    "pid",
                    "process",
                    "process-all",
                ])
                .required(true),
        )
        .get_matches();

    let files = args.get_many::<String>("file");
    let filelist = args.get_one::<String>("file-list");
    let directories = args.get_many::<String>("directory");
    let procids = args.get_one::<String>("pid");
    let procnames = args.get_many::<String>("process");
    let procall = args.get_flag("process-all");

    let format = if args.get_flag("json") {
        if args.get_flag("pretty") {
            output::Format::JsonPretty
        } else {
            output::Format::Json
        }
    } else {
        output::Format::Text
    };

    let settings = output::Settings::set(
        #[cfg(feature = "color")]
        !args.get_flag("no-color"),
        format,
        args.get_flag("maps"),
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
    } else if let Some(procnames) = procnames {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );

        let procs = procnames
            .flat_map(|procname| system.processes_by_name(procname))
            .filter_map(|proc_entry| match parse(proc_entry.exe()) {
                Ok(results) => Some(Process::new(
                    proc_entry.pid().as_u32() as usize,
                    results,
                )),
                Err(_) => None,
            })
            .collect::<Vec<Process>>();

        if procs.is_empty() {
            eprintln!("No process found");
            process::exit(1);
        }
        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(directories) = directories {
        let mut results = Vec::new();

        for directory in directories {
            let directory_path = Path::new(directory);

            if !directory_path.is_dir() {
                eprintln!("Directory {} not found", underline!(directory));
                process::exit(1);
            }

            results.append(&mut walk(directory_path));
        }

        print_binary_results(&Binaries::new(results), &settings);
    } else if let Some(files) = files {
        let mut results = Vec::new();

        for file in files {
            let file_path = Path::new(file);

            if !file_path.is_file() {
                eprintln!("File {} not found", underline!(file));
                process::exit(1);
            }

            match parse(file_path) {
                Ok(mut result) => results.append(&mut result),
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

        print_binary_results(&Binaries::new(results), &settings);
    } else if let Some(filelist) = filelist {
        let results = if filelist == "<stdin>" {
            io::stdin()
                .lock()
                .lines()
                .map(|line| {
                    line.expect("Cannot read line from standard input")
                })
                .filter_map(|file| {
                    let path = Path::new(&file);
                    if path.is_file() {
                        parse(path).ok()
                    } else {
                        None
                    }
                })
                .flatten()
                .collect()
        } else {
            filelist
                .split(char::is_control)
                .filter_map(|file| {
                    let path = Path::new(file);
                    if path.is_file() {
                        parse(path).ok()
                    } else {
                        None
                    }
                })
                .flatten()
                .collect()
        };

        print_binary_results(&Binaries::new(results), &settings);
    }
}
