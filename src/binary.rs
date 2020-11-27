#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

use checksec::elf;
use checksec::macho;
use checksec::pe;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum BinType {
    Elf32,
    Elf64,
    PE32,
    PE64,
    MachO32,
    MachO64,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Elf32 => write!(f, "ELF32"),
            Self::Elf64 => write!(f, "ELF64"),
            Self::PE32 => write!(f, "PE32"),
            Self::PE64 => write!(f, "PE64"),
            Self::MachO32 => write!(f, "MachO32"),
            Self::MachO64 => write!(f, "MachO64"),
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Elf32 => write!(f, "{}", "ELF32".bold().underline()),
            Self::Elf64 => write!(f, "{}", "ELF64".bold().underline()),
            Self::PE32 => write!(f, "{}", "PE32".bold().underline()),
            Self::PE64 => write!(f, "{}", "PE64".bold().underline()),
            Self::MachO32 => write!(f, "{}", "MachO32".bold().underline()),
            Self::MachO64 => write!(f, "{}", "MachO64".bold().underline()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    Elf(elf::CheckSecResults),
    PE(pe::CheckSecResults),
    MachO(macho::CheckSecResults),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            Self::Elf(b) => write!(f, "{}", b),
            Self::PE(b) => write!(f, "{}", b),
            Self::MachO(b) => write!(f, "{}", b),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Binary {
    pub binarytype: BinType,
    pub file: String,
    pub properties: BinSpecificProperties,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: | {} | File: {}",
            self.binarytype, self.properties, self.file
        )
    }
}
#[cfg(feature = "color")]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: | {} | {} {}",
            self.binarytype,
            self.properties,
            "File:".bold().underline(),
            self.file.bright_blue()
        )
    }
}
impl Binary {
    pub const fn new(
        binarytype: BinType,
        file: String,
        properties: BinSpecificProperties,
    ) -> Self {
        Self { binarytype, file, properties }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Binaries {
    pub binaries: Vec<Binary>,
}
impl Binaries {
    pub fn new(binaries: Vec<Binary>) -> Self {
        Self { binaries }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Process {
    pub pid: usize,
    pub binary: Vec<Binary>,
}
impl Process {
    pub fn new(pid: usize, binary: Vec<Binary>) -> Self {
        Self { pid, binary }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Processes {
    pub processes: Vec<Process>,
}
impl Processes {
    pub fn new(processes: Vec<Process>) -> Self {
        Self { processes }
    }
}
