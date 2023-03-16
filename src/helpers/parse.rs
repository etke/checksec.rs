use goblin::error::Error;
#[cfg(feature = "macho")]
use goblin::mach::{Mach, SingleArch::Archive, SingleArch::MachO};
use goblin::Object;
use memmap2::Mmap;
use std::{fmt, fs, path::Path};

use crate::helpers::binary::{BinSpecificProperties, BinType, Binary};

#[cfg(feature = "elf")]
use crate::elf;
#[cfg(feature = "macho")]
use crate::macho;
#[cfg(feature = "pe")]
use crate::pe;

pub enum ParsingError {
    Goblin(goblin::error::Error),
    IO(std::io::Error),
    #[allow(dead_code)]
    Unimplemented(&'static str),
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Goblin(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            Self::Unimplemented(str) => {
                write!(f, "Support for files of type {str} not implemented")
            }
        }
    }
}

impl From<goblin::error::Error> for ParsingError {
    fn from(err: goblin::error::Error) -> ParsingError {
        ParsingError::Goblin(err)
    }
}

impl From<std::io::Error> for ParsingError {
    fn from(err: std::io::Error) -> ParsingError {
        ParsingError::IO(err)
    }
}

pub fn parse(file: &Path) -> Result<Vec<Binary>, ParsingError> {
    let fp = fs::File::open(file)?;
    let buffer = unsafe { Mmap::map(&fp)? };

    parse_bytes(&buffer, file)
}

fn parse_bytes(
    bytes: &[u8],
    file: &Path,
) -> Result<Vec<Binary>, ParsingError> {
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
                        bin_type,
                        file.to_path_buf(),
                        BinSpecificProperties::MachO(results),
                    )])
                }
                Mach::Fat(fatmach) => {
                    let mut fat_bins: Vec<Binary> = Vec::new();
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
                                    fat_bins.push(Binary::new(
                                        bin_type,
                                        file.to_path_buf(),
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
                    Ok(fat_bins)
                }
            }
        }
        #[cfg(not(feature = "elf"))]
        Object::Elf(_) => Err(ParsingError::Unimplemented("ELF")),
        #[cfg(not(feature = "pe"))]
        Object::PE(_) => Err(ParsingError::Unimplemented("PE")),
        #[cfg(not(feature = "macho"))]
        Object::Mach(_) => Err(ParsingError::Unimplemented("MachO")),
        Object::Archive(archive) => Ok(parse_archive(&archive, file, bytes)),
        Object::Unknown(magic) => {
            Err(ParsingError::Goblin(Error::BadMagic(magic)))
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
