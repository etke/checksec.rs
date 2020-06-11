#[cfg(feature = "color")]
use colored::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use checksec::elf::ElfCheckSecResults;
use checksec::macho::MachOCheckSecResults;
use checksec::pe::PECheckSecResults;

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
            BinType::Elf32 => write!(f, "ELF32"),
            BinType::Elf64 => write!(f, "ELF64"),
            BinType::PE32 => write!(f, "PE32"),
            BinType::PE64 => write!(f, "PE64"),
            BinType::MachO32 => write!(f, "MachO32"),
            BinType::MachO64 => write!(f, "MachO64"),
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            BinType::Elf32 => write!(f, "{}", "ELF32".bold().underline()),
            BinType::Elf64 => write!(f, "{}", "ELF64".bold().underline()),
            BinType::PE32 => write!(f, "{}", "PE32".bold().underline()),
            BinType::PE64 => write!(f, "{}", "PE64".bold().underline()),
            BinType::MachO32 => write!(f, "{}", "MachO32".bold().underline()),
            BinType::MachO64 => write!(f, "{}", "MachO64".bold().underline()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    Elf(ElfCheckSecResults),
    PE(PECheckSecResults),
    MachO(MachOCheckSecResults),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            BinSpecificProperties::Elf(b) => write!(f, "{}", b),
            BinSpecificProperties::PE(b) => write!(f, "{}", b),
            BinSpecificProperties::MachO(b) => write!(f, "{}", b),
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
    pub fn new(
        binarytype: BinType,
        file: String,
        properties: BinSpecificProperties,
    ) -> Binary {
        Binary { binarytype, file, properties }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Binaries {
    pub binaries: Vec<Binary>,
}
impl Binaries {
    pub fn new(binaries: Vec<Binary>) -> Binaries {
        Binaries { binaries }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Process {
    pub pid: usize,
    pub binary: Vec<Binary>,
}
impl Process {
    pub fn new(pid: usize, binary: Vec<Binary>) -> Process {
        Process { pid, binary }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Processes {
    pub processes: Vec<Process>,
}
impl Processes {
    pub fn new(processes: Vec<Process>) -> Processes {
        Processes { processes }
    }
}
