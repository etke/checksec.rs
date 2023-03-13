#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "color", not(target_os = "windows")))]
use std::os::unix::fs::PermissionsExt;
#[cfg(all(feature = "color", not(target_os = "windows")))]
use std::path::Path;
use std::path::PathBuf;
use std::{fmt, usize};

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(feature = "macho")]
use checksec::macho;
#[cfg(feature = "pe")]
use checksec::pe;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BinType {
    #[cfg(feature = "elf")]
    Elf32,
    #[cfg(feature = "elf")]
    Elf64,
    #[cfg(feature = "pe")]
    PE32,
    #[cfg(feature = "pe")]
    PE64,
    #[cfg(feature = "macho")]
    MachO32,
    #[cfg(feature = "macho")]
    MachO64,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "ELF32"),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "ELF64"),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "PE32"),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "PE64"),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "MachO32"),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "MachO64"),
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf32 => write!(f, "{}", "ELF32".bold().underline()),
            #[cfg(feature = "elf")]
            Self::Elf64 => write!(f, "{}", "ELF64".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE32 => write!(f, "{}", "PE32".bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE64 => write!(f, "{}", "PE64".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO32 => write!(f, "{}", "MachO32".bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO64 => write!(f, "{}", "MachO64".bold().underline()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    #[cfg(feature = "elf")]
    Elf(elf::CheckSecResults),
    #[cfg(feature = "pe")]
    PE(pe::CheckSecResults),
    #[cfg(feature = "macho")]
    MachO(macho::CheckSecResults),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "elf")]
            Self::Elf(b) => write!(f, "{b}"),
            #[cfg(feature = "pe")]
            Self::PE(b) => write!(f, "{b}"),
            #[cfg(feature = "macho")]
            Self::MachO(b) => write!(f, "{b}"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Binary {
    pub binarytype: BinType,
    pub file: PathBuf,
    pub properties: BinSpecificProperties,
}
#[cfg(not(feature = "color"))]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: | {} | File: {}",
            self.binarytype,
            self.properties,
            self.file.display()
        )
    }
}
#[cfg(feature = "color")]
impl fmt::Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(target_os = "windows")]
        let filefmt = self.file.display().to_string().bright_blue();
        #[cfg(not(target_os = "windows"))]
        let filefmt = match std::fs::metadata(&self.file) {
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
                    self.file.display().to_string().white().on_red()
                } else if mode & 0o2000 == 0o2000 {
                    self.file.display().to_string().black().on_yellow()
                } else if has_filecaps(&self.file) {
                    self.file.display().to_string().black().on_blue()
                } else {
                    self.file.display().to_string().bright_blue()
                }
            }
            Err(_) => self.file.display().to_string().bright_blue(),
        };

        write!(
            f,
            "{}: | {} | {} {}",
            self.binarytype,
            self.properties,
            "File:".bold().underline(),
            filefmt
        )
    }
}
impl Binary {
    pub const fn new(
        binarytype: BinType,
        file: PathBuf,
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
