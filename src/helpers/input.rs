//! Implements functions for dealing with input in main checksec binary
use std::{
    io::{stdin, BufRead},
    path::{Path, PathBuf},
    str::FromStr,
};

use sysinfo::Pid;

#[must_use]
pub fn strings_from_stdin() -> Vec<String> {
    return stdin_to_iter()
        .flat_map(|x| x.rsplit(' ').map(str::to_string).collect::<Vec<_>>())
        .collect();
}

#[must_use]
pub fn paths_from_stdin() -> Vec<PathBuf> {
    return stdin_to_iter()
        .filter_map(|file| {
            let path = Path::new(&file);
            if path.is_file() {
                Some(path.to_path_buf())
            } else {
                None
            }
        })
        .collect();
}

#[must_use]
pub fn pids_from_stdin() -> Vec<Pid> {
    return stdin_to_iter()
        .flat_map(|x| x.rsplit(' ').map(str::to_string).collect::<Vec<_>>())
        .filter_map(|pid| Pid::from_str(&pid).ok())
        .collect();
}

#[must_use]
fn stdin_to_iter() -> Box<dyn Iterator<Item = String>> {
    return Box::new(
        stdin()
            .lock()
            .lines()
            .map(|line| line.expect("Unable to read line from stdin")),
    );
}
