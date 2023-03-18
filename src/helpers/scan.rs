#[cfg(feature = "color")]
use colored::Colorize;
use ignore::Walk;
use sysinfo::{
    PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt,
};

use std::{fs, path::PathBuf};

use crate::helpers::{binary::Binary, parse::parse, proc::Process};
use crate::underline;

#[must_use]
pub fn paths(paths: &[PathBuf]) -> Vec<Binary> {
    let mut results = Vec::new();

    for path in paths {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "Failed to check path {}: {}",
                    underline!(path.display().to_string()),
                    e
                );
                continue;
            }
        };
        if metadata.is_file() {
            match parse(path) {
                Ok(mut res) => results.append(&mut res),
                Err(msg) => {
                    eprintln!(
                        "Cannot parse binary file {}: {}",
                        underline!(path.display().to_string()),
                        msg
                    );
                }
            }
            continue;
        }
        if metadata.is_dir() {
            for entry in Walk::new(path).flatten() {
                if let Some(filetype) = entry.file_type() {
                    if filetype.is_file() {
                        if let Ok(mut res) = parse(entry.path()) {
                            results.append(&mut res);
                        }
                    }
                }
            }
            continue;
        }
        eprintln!(
            "{} is an unsupported type of file",
            underline!(path.display().to_string())
        );
    }
    results
}

#[must_use]
pub fn pids(pids: &[sysinfo::Pid]) -> Vec<Process> {
    let system = System::new_with_specifics(
        RefreshKind::new()
            .with_processes(ProcessRefreshKind::new().with_cpu()),
    );

    let mut procs = Vec::new();
    for procid in pids {
        // let process = if let Some(process) = system.process(*procid) {
        //     process
        // } else {
        //     eprintln!("No process found with ID {procid}");
        //     continue;
        // };
        let Some(process) = system.process(*procid) else {
            eprintln!("No process found with ID {procid}");
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
                procs.push(Process::new(procid.as_u32() as usize, results));
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
    procs
}

#[must_use]
pub fn procnames(procnames: &[String]) -> Vec<Process> {
    let system = System::new_with_specifics(
        RefreshKind::new()
            .with_processes(ProcessRefreshKind::new().with_cpu()),
    );

    let mut procs = Vec::new();

    for procname in procnames {
        let mut found = false;
        for proc_entry in system.processes_by_name(procname) {
            found = true;
            if let Ok(results) = parse(proc_entry.exe()) {
                procs.push(Process::new(
                    proc_entry.pid().as_u32() as usize,
                    results,
                ));
            }
        }

        if !found {
            eprintln!("No process found with name {procname}");
            continue;
        }
    }

    procs
}

#[must_use]
pub fn all_processes() -> Vec<Process> {
    let system = System::new_with_specifics(
        RefreshKind::new()
            .with_processes(ProcessRefreshKind::new().with_cpu()),
    );

    system
        .processes()
        .iter()
        .filter_map(|(pid, proc_entry)| match parse(proc_entry.exe()) {
            Ok(res) => Some(Process::new(pid.as_u32() as usize, res)),
            Err(_) => None,
        })
        .collect()
}
