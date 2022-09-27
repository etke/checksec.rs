//! Implements checksec for ELF binaries
#[cfg(feature = "color")]
use colored::Colorize;
use goblin::elf::dynamic::{
    DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_RPATH, DT_RUNPATH,
};
use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};
use goblin::elf::Elf;
use serde_derive::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "color")]
use crate::colorize_bool;
use crate::shared::{Rpath, VecRpath};

/// Relocation Read-Only mode: `None`, `Partial`, or `Full`
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Relro {
    None,
    Partial,
    Full,
}

impl fmt::Display for Relro {
    #[cfg(not(feature = "color"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<7}",
            match *self {
                Self::None => "None",
                Self::Partial => "Partial",
                Self::Full => "Full",
            }
        )
    }
    #[cfg(feature = "color")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<7}",
            match *self {
                Self::None => "None".red(),
                Self::Partial => "Partial".yellow(),
                Self::Full => "Full".green(),
            }
        )
    }
}

/// Position Independent Executable mode: `None`, `DSO`, or `PIE`
#[derive(Debug, Deserialize, Serialize)]
pub enum PIE {
    None,
    DSO,
    PIE,
}

impl fmt::Display for PIE {
    #[cfg(not(feature = "color"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<4}",
            match *self {
                Self::None => "None",
                Self::DSO => "DSO",
                Self::PIE => "Full",
            }
        )
    }
    #[cfg(feature = "color")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<4}",
            match *self {
                Self::None => "None".red(),
                Self::DSO => "DSO".yellow(),
                Self::PIE => "Full".green(),
            }
        )
    }
}

/// Fortification status: `Full`, `Partial`, `None` or `Undecidable`
#[derive(Debug, Deserialize, Serialize)]
pub enum Fortify {
    Full,
    Partial,
    None,
    Undecidable,
}

impl fmt::Display for Fortify {
    #[cfg(not(feature = "color"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<11}",
            match self {
                Self::Full => "Full",
                Self::Partial => "Partial",
                Self::None => "None",
                Self::Undecidable => "Undecidable",
            }
        )
    }
    #[cfg(feature = "color")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<11}",
            match self {
                Self::Full => "Full".green(),
                Self::Partial => "Partial".bright_green(),
                Self::None => "None".red(),
                Self::Undecidable => "Undecidable".yellow(),
            }
        )
    }
}

/// Checksec result struct for ELF32/64 binaries
///
/// **Example**
///
/// ```rust
/// use checksec::elf::CheckSecResults;
/// use goblin::elf::Elf;
/// use std::fs;
///
/// pub fn print_results(binary: &String) {
///     if let Ok(buf) = fs::read(binary) {
///         if let Ok(elf) = Elf::parse(&buf) {
///             println!("{:#?}", CheckSecResults::parse(&elf));
///         }
///     }
/// }
/// ```
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CheckSecResults {
    /// Stack Canary (*CFLAGS=*`-fstack-protector*`)
    pub canary: bool,
    /// Clang Control Flow Integrity (*CFLAGS=*`-fsanitize=cfi-*`)
    pub clang_cfi: bool,
    /// Clang SafeStack (*CFLAGS=*`-fsanitize=safe-stack`)
    pub clang_safestack: bool,
    /// Fortify (*CFLAGS=*`-D_FORTIFY_SOURCE`)
    pub fortify: Fortify,
    /// Fortified functions
    pub fortified: u32,
    /// Fortifiable functions
    pub fortifiable: u32,
    /// No Execute
    pub nx: bool,
    /// Position Inpendent Executable (*CFLAGS=*`-pie -fPIE`)
    pub pie: PIE,
    /// Relocation Read-Only
    pub relro: Relro,
    /// Run-time search path (`DT_RPATH`)
    pub rpath: VecRpath,
    /// Run-time search path (`DT_RUNTIME`)
    pub runpath: VecRpath,
}
impl CheckSecResults {
    #[must_use]
    pub fn parse(elf: &Elf) -> Self {
        let (fortified, fortifiable) = elf.has_fortified();
        let fortify = match (fortified, fortifiable) {
            (1.., 0) => Fortify::Full,
            (1.., 1..) => Fortify::Partial,
            (0, 1..) => Fortify::None,
            (0, 0) => Fortify::Undecidable,
        };
        Self {
            canary: elf.has_canary(),
            clang_cfi: elf.has_clang_cfi(),
            clang_safestack: elf.has_clang_safestack(),
            fortify,
            fortified,
            fortifiable,
            nx: elf.has_nx(),
            pie: elf.has_pie(),
            relro: elf.has_relro(),
            rpath: elf.has_rpath(),
            runpath: elf.has_runpath(),
        }
    }
}

impl fmt::Display for CheckSecResults {
    #[cfg(not(feature = "color"))]
    /// Colorized human readable format output
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Canary: {} CFI: {} SafeStack: {} Fortify: {} Fortified: {:2} \
            Fortifiable: {:2} NX: {} PIE: {} Relro: {} RPATH: {} RUNPATH: {}",
            self.canary,
            self.clang_cfi,
            self.clang_safestack,
            self.fortify,
            self.fortified,
            self.fortifiable,
            self.nx,
            self.pie,
            self.relro,
            self.rpath,
            self.runpath
        )
    }
    #[cfg(feature = "color")]
    /// Colorized human readable format output
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {:2} {} {:2} {} {} {} {} {} {} {} {} {} {}",
            "Canary:".bold(),
            colorize_bool!(self.canary),
            "CFI:".bold(),
            colorize_bool!(self.clang_cfi),
            "SafeStack:".bold(),
            colorize_bool!(self.clang_safestack),
            "Fortify:".bold(),
            self.fortify,
            "Fortified:".bold(),
            self.fortified,
            "Fortifiable:".bold(),
            self.fortifiable,
            "NX:".bold(),
            colorize_bool!(self.nx),
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

/// checksec Trait implementation for
/// [`goblin::elf::Elf`](https://docs.rs/goblin/latest/goblin/elf/struct.Elf.html)
///
/// **Example**
///
/// ```rust
/// use checksec::elf::Properties;
/// use goblin::elf::Elf;
/// use std::fs;
///
/// pub fn print_results(binary: &String) {
///     if let Ok(buf) = fs::read(binary) {
///         if let Ok(elf) = Elf::parse(&buf) {
///             println!("Canary: {}", elf.has_canary());
///         }
///     }
/// }
/// ```
pub trait Properties {
    /// check for `__stack_chk_fail` or `__intel_security_cookie` in dynstrtab
    fn has_canary(&self) -> bool;
    /// check for symbols containing `.cfi` in dynstrtab
    fn has_clang_cfi(&self) -> bool;
    /// check for `__safestack_init` in dynstrtab
    fn has_clang_safestack(&self) -> bool;
    /// check for symbols ending in `_chk` from dynstrtab
    fn has_fortify(&self) -> bool;
    /// counts fortified and fortifiable symbols from dynstrtab
    fn has_fortified(&self) -> (u32, u32);
    /// check `p_flags` of the `PT_GNU_STACK` ELF header
    fn has_nx(&self) -> bool;
    /// check `d_val` of `DT_FLAGS`/`DT_FLAGS_1` of the `PT_DYN ELF` header
    fn has_pie(&self) -> PIE;
    /// check `d_val` is `DF_BIND_NOW` for `DT_FLAGS`/`DT_FLAGS_1` of the
    /// `PT_GNU_RELRO ELF` program header
    fn has_relro(&self) -> Relro;
    /// check the`.dynamic` section for `DT_RUNPATH` and return results in a
    /// `VecRpath`
    fn has_rpath(&self) -> VecRpath;
    /// check the `.dynamic` section for `DT_RPATH` and return results in a
    /// `VecRpath`
    fn has_runpath(&self) -> VecRpath;
    /// return the corresponding string from dynstrtab for a given `d_tag`
    fn get_dynstr_by_tag(&self, tag: u64) -> Option<String>;
}

// readelf -s -W /lib/x86_64-linux-gnu/libc.so.6 | grep _chk
const FORTIFIABLE_FUNCTIONS: [&str; 79] = [
    "asprintf",
    "confstr",
    "dprintf",
    "explicit_bzero",
    "fdelt",
    "fgets",
    "fgets_unlocked",
    "fgetws",
    "fgetws_unlocked",
    "fprintf",
    "fread",
    "fread_unlocked",
    "fwprintf",
    "getcwd",
    "getdomainname",
    "getgroups",
    "gethostname",
    "getlogin_r",
    "gets",
    "getwd",
    "longjmp",
    "mbsnrtowcs",
    "mbsrtowcs",
    "mbstowcs",
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "obstack_printf",
    "obstack_vprintf",
    "poll",
    "ppoll",
    "pread64",
    "pread",
    "printf",
    "ptsname_r",
    "read",
    "readlinkat",
    "readlink",
    "realpath",
    "recv",
    "recvfrom",
    "snprintf",
    "sprintf",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "swprintf",
    "syslog",
    "ttyname_r",
    "vasprintf",
    "vdprintf",
    "vfprintf",
    "vfwprintf",
    "vprintf",
    "vsnprintf",
    "vsprintf",
    "vswprintf",
    "vsyslog",
    "vwprintf",
    "wcpcpy",
    "wcpncpy",
    "wcrtomb",
    "wcscat",
    "wcscpy",
    "wcsncat",
    "wcsncpy",
    "wcsnrtombs",
    "wcsrtombs",
    "wcstombs",
    "wctomb",
    "wmemcpy",
    "wmemmove",
    "wmempcpy",
    "wmemset",
    "wprintf",
];
/*
 * TODO: static assert that FORTIFIABLE_FUNCTIONS is sorted
 * unstable library feature 'is_sorted':
 *   const _: () = assert!(FORTIFIABLE_FUNCTIONS.is_sorted(), "must be sorted for binary search");
 */

impl Properties for Elf<'_> {
    fn has_canary(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get_at(sym.st_name) {
                match name {
                    "__stack_chk_fail" | "__intel_security_cookie" => {
                        return true
                    }
                    _ => continue,
                }
            }
        }
        false
    }
    fn has_clang_cfi(&self) -> bool {
        for sym in &self.syms {
            if let Some(name) = self.strtab.get_at(sym.st_name) {
                if name.contains(".cfi") {
                    return true;
                }
            }
        }
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get_at(sym.st_name) {
                if name.contains(".cfi") || name.contains("_cfi") {
                    return true;
                }
            }
        }
        false
    }
    fn has_clang_safestack(&self) -> bool {
        for sym in &self.dynsyms {
            if let Some(name) = self.dynstrtab.get_at(sym.st_name) {
                if name == "__safestack_init" {
                    return true;
                }
            }
        }
        false
    }
    fn has_fortify(&self) -> bool {
        for sym in &self.dynsyms {
            if !sym.is_function() {
                continue;
            }
            if let Some(name) = self.dynstrtab.get_at(sym.st_name) {
                if name.starts_with("__") && name.ends_with("_chk") {
                    return true;
                }
            }
        }
        false
    }
    fn has_fortified(&self) -> (u32, u32) {
        let mut fortified_count: u32 = 0;
        let mut fortifiable_count: u32 = 0;
        for sym in &self.dynsyms {
            if !sym.is_function() {
                continue;
            }
            if let Some(name) = self.dynstrtab.get_at(sym.st_name) {
                if name.starts_with("__") && name.ends_with("_chk") {
                    fortified_count += 1;
                } else if FORTIFIABLE_FUNCTIONS.binary_search(&name).is_ok() {
                    fortifiable_count += 1;
                }
            }
        }
        (fortified_count, fortifiable_count)
    }
    /*
    // requires running platform to be Linux
    fn has_fortifiable(&self) -> Vec<String> {
        self.dynsyms
            .iter()
            .filter(goblin::elf::Sym::is_function)
            .filter_map(|sym| self.dynstrtab.get_at(sym.st_name))
            .filter(|func| FORTIFIABLE_FUNCTIONS.binary_search(func).is_ok())
            .map(std::string::ToString::to_string)
            .collect()
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
                if DF_1_PIE & dynamic.info.flags_1 == DF_1_PIE {
                    return PIE::PIE;
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
                    if DF_BIND_NOW & dynamic.info.flags == DF_BIND_NOW
                        && DF_1_NOW & dynamic.info.flags_1 == DF_1_NOW
                    {
                        return Relro::Full;
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
                    #[allow(clippy::cast_possible_truncation)]
                    if let Some(name) =
                        self.dynstrtab.get_at(dynamic.d_val as usize)
                    {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }
}
