use colored::*;
use goblin::elf::dynamic::{
    DF_1_PIE, DF_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_RPATH, DT_RUNPATH,
};
use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};
use goblin::elf::Elf;

use serde_derive::{Deserialize, Serialize};

use std::fmt;

use crate::shared::{colorize_bool, Rpath, VecRpath};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum Relro {
    None,
    Partial,
    Full,
}
impl fmt::Display for Relro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Relro::None => write!(f, "{}", "None".red()),
            Relro::Partial => write!(f, "{}", "Partial".yellow()),
            Relro::Full => write!(f, "{}", "Full".green()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PIE {
    None,
    DSO,
    PIE,
}
impl fmt::Display for PIE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PIE::None => write!(f, "{}", "None".red()),
            PIE::DSO => write!(f, "{}", "DSO".yellow()),
            PIE::PIE => write!(f, "{}", "Full".green()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ElfCheckSecResults {
    canary: bool,
    clang_cfi: bool,
    clang_safestack: bool,
    fortify: bool,
    fortified: u32,
    //fortifiable:  Option<Vec<OsString>>,
    nx: bool,
    pie: PIE,
    relro: Relro,
    rpath: VecRpath,
    runpath: VecRpath,
}

impl ElfCheckSecResults {
    pub fn parse(elf: &Elf) -> ElfCheckSecResults {
        ElfCheckSecResults {
            canary: elf.has_canary(),
            clang_cfi: elf.has_clang_cfi(),
            clang_safestack: elf.has_clang_safestack(),
            fortify: elf.has_fortify(),
            fortified: elf.has_fortified(),
            nx: elf.has_nx(),
            pie: elf.has_pie(),
            relro: elf.has_relro(),
            rpath: elf.has_rpath(),
            runpath: elf.has_runpath(),
        }
    }
}
impl fmt::Display for ElfCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            "Canary:".bold(),
            colorize_bool(self.canary),
            "CFI:".bold(),
            colorize_bool(self.clang_cfi),
            "SafeStack:".bold(),
            colorize_bool(self.clang_safestack),
            "Fortify:".bold(),
            colorize_bool(self.fortify),
            "Fortified:".bold(),
            self.fortified,
            "NX:".bold(),
            colorize_bool(self.nx),
            "PIE:".bold(),
            self.pie,
            "Relro:".bold(),
            self.relro,
            "RPATH:".bold(),
            self.rpath,
            "RUNPATH:".bold(),
            self.runpath
        )
    }
}

pub trait ElfProperties {
    fn has_canary(&self) -> bool;
    fn has_clang_cfi(&self) -> bool;
    fn has_clang_safestack(&self) -> bool;
    fn has_fortify(&self) -> bool;
    fn has_fortified(&self) -> u32;
    // requires running platform to be Linux
    //fn has_fortifiable(&self) -> u32;
    fn has_nx(&self) -> bool;
    fn has_pie(&self) -> PIE;
    fn has_relro(&self) -> Relro;
    fn has_rpath(&self) -> VecRpath;
    fn has_runpath(&self) -> VecRpath;
    fn get_dynstr_by_tag(&self, tag: u64) -> Option<String>;
}

impl ElfProperties for Elf<'_> {
    fn has_canary(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    match name {
                        "__stack_chk_fail" => return true,
                        "__intel_security_cookie" => return true,
                        _ => continue,
                    }
                }
            }
        }
        false
    }
    fn has_clang_cfi(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    if name.contains(".cfi") {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn has_clang_safestack(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    if name == "__safestack_init" {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn has_fortify(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    if name.ends_with("_chk") {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn has_fortified(&self) -> u32 {
        let mut fortified_count: u32 = 0;
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get(sym.st_name) {
                if let Ok(name) = name {
                    if name.ends_with("_chk") {
                        fortified_count += 1;
                    }
                }
            }
        }
        fortified_count
    }
    /*
    // requires running platform to be Linux
    fn has_forifiable(&self) -> Option<Vec<OsString>> {
    }
    */
    fn has_nx(&self) -> bool {
        for header in &self.program_headers {
            if header.p_type == PT_GNU_STACK {
                if PF_X != header.p_flags & PF_X {
                    return true;
                }
                break;
            }
        }
        false
    }
    fn has_pie(&self) -> PIE {
        if self.header.e_type == ET_DYN {
            if let Some(dynamic) = &self.dynamic {
                for dyns in &dynamic.dyns {
                    if dyns.d_tag == DT_FLAGS
                        || dyns.d_tag == DT_FLAGS_1
                            && DF_1_PIE & dyns.d_val != DF_1_PIE
                    {
                        return PIE::PIE;
                    }
                }
            }
            return PIE::DSO;
        }
        PIE::None
    }
    fn has_relro(&self) -> Relro {
        for header in &self.program_headers {
            if header.p_type == PT_GNU_RELRO {
                if let Some(dynamic) = &self.dynamic {
                    for dyns in &dynamic.dyns {
                        if dyns.d_tag == DT_FLAGS
                            || dyns.d_tag == DT_FLAGS_1
                                && DF_BIND_NOW & dyns.d_val == 0
                        {
                            return Relro::Full;
                        }
                    }
                }
                return Relro::Partial;
            }
        }
        Relro::None
    }
    fn has_rpath(&self) -> VecRpath {
        if self.dynamic.is_some() {
            if let Some(name) = self.get_dynstr_by_tag(DT_RPATH) {
                return VecRpath::new(
                    name.split(':')
                        .map(|path| Rpath::Yes(path.to_string()))
                        .collect(),
                );
            }
        }
        VecRpath::new(vec![Rpath::None])
    }
    fn has_runpath(&self) -> VecRpath {
        if self.dynamic.is_some() {
            if let Some(name) = self.get_dynstr_by_tag(DT_RUNPATH) {
                return VecRpath::new(
                    name.split(':')
                        .map(|path| Rpath::Yes(path.to_string()))
                        .collect(),
                );
            }
        }
        VecRpath::new(vec![Rpath::None])
    }
    fn get_dynstr_by_tag(&self, tag: u64) -> Option<String> {
        if let Some(dynamic) = &self.dynamic {
            for dynamic in &dynamic.dyns {
                if dynamic.d_tag == tag {
                    if let Some(name) =
                        self.dynstrtab.get(dynamic.d_val as usize)
                    {
                        if let Ok(name) = name {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
        None
    }
}
