#![warn(clippy::pedantic)]
// Do not require 1.65.0
#![allow(clippy::manual_let_else)]
extern crate clap;
extern crate core;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{
    crate_authors, crate_description, crate_version, Arg, ArgAction, ArgGroup,
    Command,
};
#[cfg(all(feature = "maps", target_os = "linux"))]
use either::Either;
use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::{Mach, SingleArch::Archive, SingleArch::MachO};
use goblin::Object;
use ignore::Walk;
#[cfg(all(feature = "maps", target_os = "linux"))]
use itertools::Itertools;
use memmap2::Mmap;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use serde_json::{json, to_string_pretty};
use sysinfo::{
    PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt,
};

use std::collections::HashMap;
#[cfg(all(target_os = "linux", feature = "elf"))]
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::ErrorKind;
#[cfg(all(feature = "color", not(target_os = "windows")))]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::{env, fmt, fs, process};

#[cfg(feature = "color")]
use colored::{ColoredString, Colorize};

#[cfg(feature = "color")]
use colored_json::to_colored_json_auto;

mod binary;
mod proc;

use binary::{BinSpecificProperties, BinType, Binary, Blob};
use proc::{Process, Processes};

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::elf::LibraryLookup;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::ldso::LdSoError;
#[cfg(feature = "macho")]
use checksec::macho;
use checksec::output;
#[cfg(feature = "pe")]
use checksec::pe;
#[cfg(all(target_os = "linux", feature = "elf"))]
use checksec::shared::VecRpath;
use checksec::{bold, underline};

#[cfg(all(feature = "color", target_os = "windows"))]
fn print_filename(file: &Path) -> ColoredString {
    file.display().to_string().bright_blue()
}

#[cfg(all(feature = "color", not(target_os = "windows")))]
fn print_filename(file: &Path) -> ColoredString {
    match std::fs::metadata(file) {
        Ok(md) => {
            #[cfg(target_os = "linux")]
            fn has_filecaps(file: &Path) -> bool {
                xattr::get(file, "security.capability")
                    .unwrap_or(None)
                    .is_some()
            }
            #[cfg(not(target_os = "linux"))]
            fn has_filecaps(_file: &Path) -> bool {
                false
            }

            let mode = md.permissions().mode();
            if mode & 0o4000 == 0o4000 {
                file.display().to_string().white().on_red()
            } else if mode & 0o2000 == 0o2000 {
                file.display().to_string().black().on_yellow()
            } else if has_filecaps(file) {
                file.display().to_string().black().on_blue()
            } else {
                file.display().to_string().bright_blue()
            }
        }
        Err(_) => file.display().to_string().bright_blue(),
    }
}

#[cfg(not(feature = "color"))]
fn print_filename(file: &Path) -> impl std::fmt::Display + '_ {
    file.display()
}

fn print_binary_results(binaries: &[Binary], settings: &output::Settings) {
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
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
        }
        output::Format::Text => {
            let mut first = true;

            for binary in binaries {
                if !first && settings.libraries {
                    println!();
                }
                first = false;

                for blob in &binary.blobs {
                    println!(
                        "{}: | {} | {} {}",
                        blob.binarytype,
                        blob.properties,
                        underline!(bold!("File:")),
                        print_filename(&binary.file)
                    );
                }
                if settings.libraries {
                    for library in &binary.libraries {
                        for blob in &library.blobs {
                            println!(
                                "{}: | {} | {} {}",
                                blob.binarytype,
                                blob.properties,
                                underline!(bold!("File:")),
                                print_filename(&library.file)
                            );
                        }
                    }
                }
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
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
        }
        output::Format::Text => {
            let mut first = true;

            for process in &processes.processes {
                if !first && settings.libraries {
                    println!();
                }
                first = false;

                for blob in &process.binary.blobs {
                    println!(
                        "{}({})\n \u{21aa} {}: | {} | {} {}",
                        bold!(process
                            .binary
                            .file
                            .file_name()
                            .unwrap_or_else(|| OsStr::new("n/a"))
                            .to_string_lossy()),
                        process.pid,
                        blob.binarytype,
                        blob.properties,
                        underline!(bold!("File:")),
                        print_filename(&process.binary.file)
                    );
                }

                #[cfg(all(
                    feature = "maps",
                    any(target_os = "linux", target_os = "windows")
                ))]
                if let Some(libraries) = &process.libraries {
                    for library in libraries {
                        for blob in &library.blobs {
                            println!(
                                " \u{21aa} {}: | {} | {} {}",
                                blob.binarytype,
                                blob.properties,
                                underline!(bold!("File:")),
                                print_filename(&library.file)
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
                            println!("\t{map}");
                        }
                    }
                }
            }
        }
    }
}

struct Lookup {
    #[cfg(all(target_os = "linux", feature = "elf"))]
    elf: LibraryLookup,
}

impl Lookup {
    #[cfg(all(target_os = "linux", feature = "elf"))]
    fn elf_lookup(
        &self,
        binarypath: &Path,
        rpath: &VecRpath,
        runpath: &VecRpath,
        libfilename: &str,
    ) -> Option<PathBuf> {
        self.elf.lookup(binarypath, rpath, runpath, libfilename)
    }
}

enum ParseError {
    Goblin(goblin::error::Error),
    IO(std::io::Error),
    #[cfg(all(target_os = "linux", feature = "elf"))]
    LdSo(LdSoError),
    #[allow(dead_code)]
    Unimplemented(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Goblin(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            #[cfg(all(target_os = "linux", feature = "elf"))]
            Self::LdSo(e) => {
                write!(f, "Failed to initialize library lookup: {e}")
            }
            Self::Unimplemented(str) => {
                write!(f, "Support for files of type {str} not implemented")
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

#[cfg(all(target_os = "linux", feature = "elf"))]
impl From<LdSoError> for ParseError {
    fn from(err: LdSoError) -> ParseError {
        ParseError::LdSo(err)
    }
}

type Cache = Arc<Mutex<HashMap<PathBuf, Vec<Binary>>>>;

fn parse(
    file: &Path,
    cache: &mut Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    if let Some(ref mut cache) = cache {
        let cache = cache.lock().unwrap();
        if let Some(entry) = cache.get(file) {
            return Ok(entry.clone());
        }
    }

    let fp = fs::File::open(file)?;
    let buffer = unsafe { Mmap::map(&fp)? };

    let result = parse_bytes(&buffer, file)?;
    if let Some(ref mut cache) = cache {
        let mut cache = cache.lock().unwrap();
        cache.insert(file.to_path_buf(), result.clone());
    }

    Ok(result)
}

#[allow(clippy::too_many_lines)]
fn parse_bytes(bytes: &[u8], file: &Path) -> Result<Vec<Binary>, ParseError> {
    match Object::parse(bytes)? {
        #[cfg(feature = "elf")]
        Object::Elf(elf) => {
            let results = elf::CheckSecResults::parse(&elf, bytes);
            let bin_type =
                if elf.is_64 { BinType::Elf64 } else { BinType::Elf32 };
            Ok(vec![Binary::new(
                file.to_path_buf(),
                vec![Blob::new(bin_type, BinSpecificProperties::Elf(results))],
            )])
        }
        #[cfg(feature = "pe")]
        Object::PE(pe) => {
            let results = pe::CheckSecResults::parse(&pe, bytes);
            let bin_type =
                if pe.is_64 { BinType::PE64 } else { BinType::PE32 };
            Ok(vec![Binary::new(
                file.to_path_buf(),
                vec![Blob::new(bin_type, BinSpecificProperties::PE(results))],
            )])
        }
        #[cfg(feature = "macho")]
        Object::Mach(mach) => {
            match mach {
                Mach::Binary(macho) => {
                    let results = macho::CheckSecResults::parse(&macho);
                    let bin_type = if macho.is_64 {
                        BinType::MachO64
                    } else {
                        BinType::MachO32
                    };
                    Ok(vec![Binary::new(
                        file.to_path_buf(),
                        vec![Blob::new(
                            bin_type,
                            BinSpecificProperties::MachO(results),
                        )],
                    )])
                }
                Mach::Fat(fatmach) => {
                    let mut fat_bins: Vec<Binary> = Vec::new();
                    let mut fat_blobs: Vec<Blob> = Vec::new();
                    for (idx, fatarch) in fatmach.iter_arches().enumerate() {
                        if let Ok(container) = fatmach.get(idx) {
                            match container {
                                MachO(mach) => {
                                    let results =
                                        macho::CheckSecResults::parse(&mach);
                                    let bin_type = if mach.is_64 {
                                        BinType::MachO64
                                    } else {
                                        BinType::MachO32
                                    };
                                    fat_blobs.push(Blob::new(
                                        bin_type,
                                        BinSpecificProperties::MachO(results),
                                    ));
                                }
                                Archive(archive) => {
                                    let fatarch = fatarch?;
                                    if let Some(archive_bytes) = bytes.get(
                                        fatarch.offset as usize
                                            ..(fatarch.offset + fatarch.size)
                                                as usize,
                                    ) {
                                        fat_bins.append(&mut parse_archive(
                                            &archive,
                                            file,
                                            archive_bytes,
                                        ));
                                    } else {
                                        Err(goblin::error::Error::Malformed("Archive refers to invalid position".to_string()))?;
                                    }
                                }
                            }
                        }
                    }
                    fat_bins.push(Binary::new(file.to_path_buf(), fat_blobs));
                    Ok(fat_bins)
                }
            }
        }
        #[cfg(not(feature = "elf"))]
        Object::Elf(_) => Err(ParseError::Unimplemented("ELF")),
        #[cfg(not(feature = "pe"))]
        Object::PE(_) => Err(ParseError::Unimplemented("PE")),
        #[cfg(not(feature = "macho"))]
        Object::Mach(_) => Err(ParseError::Unimplemented("MachO")),
        Object::Archive(archive) => Ok(parse_archive(&archive, file, bytes)),
        Object::Unknown(magic) => {
            Err(ParseError::Goblin(Error::BadMagic(magic)))
        }
    }
}

fn parse_archive(
    archive: &goblin::archive::Archive,
    file: &Path,
    bytes: &[u8],
) -> Vec<Binary> {
    archive
        .members()
        .iter()
        .filter_map(|member_name| match archive.extract(member_name, bytes) {
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
        })
        .flatten()
        .collect()
}

#[cfg(not(all(target_os = "linux", feature = "elf")))]
fn parse_single_file(
    file: &Path,
    _scan_dynlibs: bool,
) -> Result<Vec<Binary>, ParseError> {
    parse(file, &mut None)
}

#[cfg(not(all(target_os = "linux", feature = "elf")))]
fn parse_file_impl(
    file: &Path,
    _scan_dynlibs: bool,
    _lookup: &Option<Lookup>,
    cache: &mut Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    parse(file, cache)
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn scan_dependencies(
    binary: &Binary,
    lookup: &Lookup,
    scanned: &HashSet<PathBuf>,
) -> HashSet<PathBuf> {
    let mut to_scan = HashSet::new();

    for blob in &binary.blobs {
        #[allow(irrefutable_let_patterns)]
        if let BinSpecificProperties::Elf(elf_properties) = &blob.properties {
            for dynlib in &elf_properties.dynlibs {
                match lookup.elf_lookup(
                    &binary.file,
                    &elf_properties.rpath,
                    &elf_properties.runpath,
                    dynlib,
                ) {
                    Some(path) => {
                        if scanned.contains(&path) {
                            continue;
                        }
                        to_scan.insert(path);
                    }
                    None => {
                        eprintln!(
                            "Library {} for {} not found",
                            underline!(dynlib),
                            binary.file.display()
                        );
                    }
                }
            }
        }
    }

    to_scan
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn parse_dependencies(
    binary: &mut Binary,
    lookup: &Lookup,
    cache: &Option<Cache>,
) {
    let mut scanned = HashSet::new();
    let mut to_scan = scan_dependencies(binary, lookup, &scanned);

    while !to_scan.is_empty() {
        let mut results: Vec<Binary> = to_scan
            .par_iter()
            .filter_map(|lib| {
                match parse(lib, &mut cache.as_ref().map(Arc::clone)) {
                    Ok(bins) => Some(bins),
                    Err(err) => {
                        eprintln!(
                            "Failed to parse {} for {}: {}",
                            lib.display(),
                            binary.file.display(),
                            err
                        );
                        None
                    }
                }
            })
            .flatten()
            .collect();

        scanned.extend(to_scan);

        to_scan = results
            .par_iter()
            .flat_map(|bin| scan_dependencies(bin, lookup, &scanned))
            .collect();

        binary.libraries.append(&mut results);
    }
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn parse_file_impl(
    file: &Path,
    scan_dynlibs: bool,
    lookup: &Option<Lookup>,
    cache: &mut Option<Cache>,
) -> Result<Vec<Binary>, ParseError> {
    let mut results = parse(file, cache)?;

    if !scan_dynlibs || lookup.is_none() {
        return Ok(results);
    }

    let lookup = lookup.as_ref().unwrap();

    for result in &mut results {
        parse_dependencies(result, lookup, cache);
    }

    Ok(results)
}

#[cfg(all(target_os = "linux", feature = "elf"))]
fn parse_single_file(
    file: &Path,
    scan_dynlibs: bool,
) -> Result<Vec<Binary>, ParseError> {
    if !scan_dynlibs {
        return parse(file, &mut None);
    }

    let lookup = Lookup { elf: LibraryLookup::new()? };

    parse_file_impl(file, true, &Some(lookup), &mut None)
}

fn walk(
    basepath: &Path,
    scan_dynlibs: bool,
    output_settings: &output::Settings,
) {
    let lookup = if scan_dynlibs {
        Some(Lookup {
            #[cfg(all(target_os = "linux", feature = "elf"))]
            elf: LibraryLookup::new().unwrap_or_else(|err| {
                eprintln!("Failed to initialize library lookup: {err}");
                process::exit(1)
            }),
        })
    } else {
        None
    };

    let cache = Arc::new(Mutex::new(HashMap::new()));

    let bins: Vec<Binary> = Walk::new(basepath)
        .flatten()
        .filter(|entry| {
            entry.file_type().filter(std::fs::FileType::is_file).is_some()
        })
        .par_bridge()
        .filter_map(|entry| {
            parse_file_impl(
                entry.path(),
                scan_dynlibs,
                &lookup,
                &mut Some(Arc::clone(&cache)),
            )
            .ok()
        })
        .flatten()
        .collect();

    print_binary_results(&bins, output_settings);
}

#[cfg(all(feature = "maps", target_os = "linux"))]
fn parse_process_libraries(
    process: &sysinfo::Process,
    cache: &mut Option<Cache>,
) -> Result<Vec<Binary>, std::io::Error> {
    Ok(Process::parse_maps(process.pid().as_u32() as usize)?
        .into_iter()
        .filter(|m| m.flags.x)
        .filter_map(|m| m.pathname)
        .filter(|p| p.is_absolute() && p != process.exe())
        .map(|p| match p.file_name() {
            Some(file_name) => match file_name.to_str() {
                Some(file_name) => {
                    match file_name.strip_suffix(" (deleted)") {
                        Some(s) => {
                            let mut pb = PathBuf::from(
                                p.parent().unwrap_or(Path::new("/")),
                            );
                            pb.push(s);
                            Either::Left(pb)
                        }
                        None => Either::Right(p),
                    }
                }
                None => Either::Right(p),
            },
            None => Either::Right(p),
        })
        .unique()
        .par_bridge()
        .filter_map(|p| {
            parse(&p, &mut cache.as_ref().map(Arc::clone))
                .map_err(|err| {
                    if let ParseError::IO(ref e) = err {
                        if e.kind() == ErrorKind::NotFound
                            || e.kind() == ErrorKind::PermissionDenied
                        {
                            return;
                        }
                    }

                    eprintln!(
                        "Failed to parse '{}' for process ID {}: {}",
                        p.display(),
                        process.pid(),
                        err
                    );
                })
                .ok()
        })
        .flatten()
        .collect::<Vec<Binary>>())
}

#[cfg(not(all(feature = "maps", target_os = "linux")))]
fn parse_process_libraries(
    _process: &sysinfo::Process,
    _cache: &mut Option<Cache>,
) -> Result<Vec<Binary>, std::io::Error> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "parse_process_libraries()",
    ))
}

fn parse_processes<'a, I>(processes: I, scan_dynlibs: bool) -> Vec<Process>
where
    I: Iterator<Item = &'a sysinfo::Process> + Send,
{
    let cache = Arc::new(Mutex::new(HashMap::new()));

    processes
        .par_bridge()
        .filter_map(|process| {
            match parse(process.exe(), &mut Some(Arc::clone(&cache))) {
                Err(err) => {
                    if let ParseError::IO(ref e) = err {
                        if e.kind() == ErrorKind::NotFound
                            || e.kind() == ErrorKind::PermissionDenied
                        {
                            return None;
                        }
                    }

                    eprintln!(
                        "Can not parse process {} with ID {}: {}",
                        process.name(),
                        process.pid(),
                        err
                    );

                    None
                }
                Ok(bins) => Some(
                    bins.into_iter()
                        .map(|bin| {
                            Process::new(
                                process.pid().as_u32() as usize,
                                bin,
                                if scan_dynlibs {
                                    parse_process_libraries(
                                        process,
                                        &mut Some(Arc::clone(&cache)),
                                    )
                                    .ok()
                                } else {
                                    None
                                },
                            )
                        })
                        .collect::<Vec<proc::Process>>(),
                ),
            }
        })
        .flatten()
        .collect()
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
                .help("Target directory"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("Target file"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output in json format"),
        )
        .arg(
            Arg::new("libraries")
                .short('l')
                .long("libraries")
                .action(ArgAction::SetTrue)
                .help("Include all shared loaded libraries (Linux only)")
                .requires("directory")
                .requires("file")
                .requires("pid")
                .requires("process")
                .requires("process-all"),
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
                .conflicts_with_all(["directory", "file"]),
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
                .args(["directory", "file", "pid", "process", "process-all"])
                .required(true),
        )
        .get_matches();

    // required operation
    let file = args.get_one::<String>("file");
    let directory = args.get_one::<String>("directory");
    let procids = args.get_one::<String>("pid");
    let procname = args.get_one::<String>("process");
    let procall = args.get_flag("process-all");

    // optional modifiers
    let libraries = args.get_flag("libraries");

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
        libraries,
    );

    if procall {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );

        let procs = parse_processes(system.processes().values(), libraries);

        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(procids) = procids {
        let procids: Vec<sysinfo::Pid> = procids
            .split(',')
            .map(|id| match id.parse::<sysinfo::Pid>() {
                Ok(id) => id,
                Err(msg) => {
                    eprintln!("Invalid process ID {id}: {msg}");
                    process::exit(1);
                }
            })
            .collect();
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );

        let procs = parse_processes(
            procids
                .iter()
                .filter_map(|&pid| {
                    system.process(pid).or_else(|| {
                        eprintln!("No process found with ID {pid}");
                        None
                    })
                })
                .filter(|process| {
                    if process.exe().is_file() {
                        true
                    } else {
                        eprintln!(
                "No valid executable found for process {} with ID {}: {}",
                process.name(),
                process.pid(),
                process.exe().display()
            );
                        false
                    }
                }),
            libraries,
        );

        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(procname) = procname {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_cpu()),
        );

        let procs = parse_processes(
            system
                .processes_by_name(procname)
                // TODO: processes_by_name() should return a Iterator implementing the trait Send
                .collect::<Vec<&sysinfo::Process>>()
                .into_iter(),
            libraries,
        );

        if procs.is_empty() {
            eprintln!("No process found matching name {procname}");
            process::exit(1);
        }
        print_process_results(&Processes::new(procs), &settings);
    } else if let Some(directory) = directory {
        let directory_path = Path::new(directory);

        if !directory_path.is_dir() {
            eprintln!("Directory {} not found", underline!(directory));
            process::exit(1);
        }

        walk(directory_path, libraries, &settings);
    } else if let Some(file) = file {
        let file_path = Path::new(file);

        if !file_path.is_file() {
            eprintln!("File {} not found", underline!(file));
            process::exit(1);
        }

        match parse_single_file(file_path, libraries) {
            Ok(result) => {
                print_binary_results(&result, &settings);
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
