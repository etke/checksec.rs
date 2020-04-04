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

#[derive(Deserialize, Serialize)]
pub struct Binaries {
    pub binaries: Vec<Binary>,
}
