#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(all(feature = "maps", target_os = "linux"))]
use std::fs;
#[cfg(all(feature = "maps", target_os = "linux"))]
use std::io::Error;
#[cfg(all(feature = "maps", target_os = "linux"))]
use std::io::ErrorKind;
#[cfg(all(feature = "maps", target_os = "linux"))]
use std::path::PathBuf;
use std::usize;

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
            Self::Elf(b) => write!(f, "{}", b),
            #[cfg(feature = "pe")]
            Self::PE(b) => write!(f, "{}", b),
            #[cfg(feature = "macho")]
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

#[cfg(all(feature = "maps", target_os = "linux"))]
#[derive(Deserialize, Serialize)]
pub struct Region {
    pub start: usize,
    pub end: usize,
}
#[cfg(all(feature = "maps", target_os = "linux"))]
impl Region {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

#[cfg(all(feature = "maps", target_os = "linux"))]
#[derive(Deserialize, Serialize)]
pub struct MapFlags {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}
#[cfg(all(feature = "maps", target_os = "linux"))]
impl MapFlags {
    pub fn new(flagstr: &str) -> Self {
        let r = flagstr.get(0..1) == Some("r");
        let w = flagstr.get(1..2) == Some("w");
        let x = flagstr.get(2..3) == Some("x");
        Self { r, w, x }
    }
}
#[cfg(all(not(feature = "color"), feature = "maps", target_os = "linux"))]
impl fmt::Display for MapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.r { "r" } else { "-" },
            if self.w { "w" } else { "-" },
            if self.x { "x" } else { "-" }
        )
    }
}
#[cfg(all(feature = "color", feature = "maps", target_os = "linux"))]
impl fmt::Display for MapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.r & self.w & self.x {
            return write!(f, "{}", "rwx".red());
        }
        write!(
            f,
            "{}{}{}",
            if self.r { "r" } else { "-" },
            if self.w { "w" } else { "-" },
            if self.x { "x" } else { "-" }
        )
    }
}

#[cfg(all(feature = "maps", target_os = "linux"))]
#[derive(Deserialize, Serialize)]
pub struct MapEntry {
    pub region: Region,
    pub flags: MapFlags,
    pub pathname: Option<PathBuf>,
}
#[cfg(all(not(feature = "color"), feature = "maps", target_os = "linux"))]
impl fmt::Display for MapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x}->0x{:x} {} {}",
            self.region.start,
            self.region.end,
            self.flags,
            match &self.pathname {
                Some(pathname) => pathname.display().to_string(),
                None => "".to_string(),
            }
        )
    }
}
#[cfg(all(feature = "color", feature = "maps", target_os = "linux"))]
impl fmt::Display for MapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.flags.r & self.flags.w & self.flags.x {
            write!(
                f,
                "{} {}",
                format!(
                    "0x{:x}->0x{:x} {}",
                    self.region.start, self.region.end, self.flags
                )
                .red(),
                match &self.pathname {
                    Some(pathname) => pathname.display().to_string().red(),
                    None => "".to_string().red(),
                }
            )
        } else {
            write!(
                f,
                "0x{:x}->0x{:x} {} {}",
                self.region.start,
                self.region.end,
                self.flags,
                match &self.pathname {
                    Some(pathname) => pathname.display().to_string(),
                    None => "".to_string(),
                }
            )
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Process {
    pub pid: usize,
    pub binary: Vec<Binary>,
    #[cfg(all(feature = "maps", target_os = "linux"))]
    pub maps: Option<Vec<MapEntry>>,
}
impl Process {
    #[cfg(any(not(feature = "maps"), not(target_os = "linux")))]
    pub fn new(pid: usize, binary: Vec<Binary>) -> Self {
        Self { pid, binary }
    }
    #[cfg(all(feature = "maps", target_os = "linux"))]
    pub fn new(pid: usize, binary: Vec<Binary>) -> Self {
        match Process::parse_maps(pid) {
            Ok(maps) => Self { pid, binary, maps: Some(maps) },
            Err(_) => Self { pid, binary, maps: None },
        }
    }
    #[cfg(all(feature = "maps", target_os = "linux"))]
    pub fn parse_maps(pid: usize) -> Result<Vec<MapEntry>, Error> {
        let mut maps: Vec<MapEntry> = Vec::new();
        if let Ok(maps_str) = fs::read_to_string(format!("/proc/{}/maps", pid))
        {
            for line in maps_str.lines() {
                let mut split_line = line.split_whitespace();
                let (start_str, end_str) = split_line
                    .next()
                    .ok_or(ErrorKind::InvalidData)?
                    .split_once('-')
                    .ok_or(ErrorKind::InvalidData)?;
                let region = Region::new(
                    usize::from_str_radix(start_str, 16).unwrap_or(0),
                    usize::from_str_radix(end_str, 16).unwrap_or(0),
                );
                let flags = MapFlags::new(
                    split_line.next().ok_or(ErrorKind::InvalidData)?,
                );
                split_line.next(); // skip offset
                split_line.next(); // skip dev
                split_line.next(); // skip inode
                let pathname =
                    Some(split_line.collect::<Vec<&str>>().join(" "))
                        .filter(|x| !x.is_empty())
                        .map(PathBuf::from);
                maps.push(MapEntry { region, flags, pathname });
            }
            return Ok(maps);
        }
        Err(Error::last_os_error())
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
