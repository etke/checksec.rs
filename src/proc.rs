#[cfg(all(
    feature = "color",
    feature = "maps",
    not(target_os = "macos")
))]
use colored::Colorize;
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "maps", not(target_os = "macos")))]
use std::fmt;

use std::usize;
#[cfg(all(feature = "maps", target_os = "linux"))]
use std::{fs, io::ErrorKind};
#[cfg(all(
    feature = "maps",
    any(target_os = "linux", target_os = "windows")
))]
use std::{io::Error, path::PathBuf};

#[cfg(all(feature = "maps", target_os = "windows"))]
use windows::Win32::{
    Foundation::CloseHandle,
    Security::AdjustTokenPrivileges,
    System::{
        Diagnostics::{
            Debug::{GetThreadContext, CONTEXT},
            ToolHelp::{
                CreateToolhelp32Snapshot, Heap32First, Heap32ListFirst,
                Heap32ListNext, Heap32Next, Module32FirstW, Module32NextW,
                Thread32First, Thread32Next, HEAPENTRY32, HEAPLIST32,
                MODULEENTRY32W, TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
            },
        },
        Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_GUARD, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY,
        },
        Threading::{
            GetCurrentThreadId, OpenProcess, OpenThread, ResumeThread,
            SuspendThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
            THREAD_SUSPEND_RESUME,
        },
    },
};

#[cfg(all(feature = "maps", target_os = "windows"))]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HANDLE, LUID},
        Security::{
            LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

#[cfg(all(feature = "maps", target_os = "windows"))]
use std::{
    ffi::{c_void, OsStr},
    iter::once,
    mem,
    os::windows::ffi::OsStrExt,
};

use crate::binary::Binary;

#[cfg(all(feature = "maps", any(target_os = "linux", target_os = "windows")))]
#[derive(Deserialize, Serialize)]
pub struct Region {
    pub start: usize,
    pub end: usize,
}
#[cfg(all(feature = "maps", any(target_os = "linux", target_os = "windows")))]
impl Region {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[cfg(all(feature = "maps", any(target_os = "linux", target_os = "windows")))]
#[derive(Deserialize, Serialize)]
pub struct MapFlags {
    pub r: bool,
    pub w: bool,
    pub x: bool,
    #[cfg(all(feature = "maps", target_os = "windows"))]
    pub guard: bool,
}
#[cfg(all(feature = "maps", any(target_os = "linux", target_os = "windows")))]
impl MapFlags {
    #[cfg(target_os = "linux")]
    pub fn new(flagstr: &str) -> Self {
        let r = flagstr.get(0..1) == Some("r");
        let w = flagstr.get(1..2) == Some("w");
        let x = flagstr.get(2..3) == Some("x");
        Self { r, w, x }
    }
    #[cfg(target_os = "windows")]
    pub fn new(flags: PAGE_PROTECTION_FLAGS) -> Self {
        let r = flags
            & (PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
                | PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY)
            != PAGE_PROTECTION_FLAGS(0);
        let w = flags
            & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_WRITECOPY)
            != PAGE_PROTECTION_FLAGS(0);
        let x = flags
            & (PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY)
            != PAGE_PROTECTION_FLAGS(0);
        let guard = flags & (PAGE_GUARD) != PAGE_PROTECTION_FLAGS(0);
        Self { r, w, x, guard }
    }
}
#[cfg(all(
    not(feature = "color"),
    feature = "maps",
    any(target_os = "linux", target_os = "windows")
))]
impl fmt::Display for MapFlags {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.r { "r" } else { "-" },
            if self.w { "w" } else { "-" },
            if self.x { "x" } else { "-" }
        )
    }
    #[cfg(target_os = "windows")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.r { "r" } else { "-" },
            if self.w { "w" } else { "-" },
            if self.x { "x" } else { "-" },
            if self.x { "g" } else { "-" }
        )
    }
}
#[cfg(all(
    feature = "color",
    feature = "maps",
    any(target_os = "linux", target_os = "windows")
))]
impl fmt::Display for MapFlags {
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "windows")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.r & self.w & self.x && (!self.guard) {
            return write!(f, "{}", "rwx-".red());
        }
        write!(
            f,
            "{}{}{}{}",
            if self.r { "r" } else { "-" },
            if self.w { "w" } else { "-" },
            if self.x { "x" } else { "-" },
            if self.x { "g" } else { "-" }
        )
    }
}

#[cfg(all(feature = "maps", target_os = "windows"))]
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MapType {
    Heap,
    Module,
    Stack,
    Private,
}
#[cfg(all(feature = "maps", target_os = "windows"))]
impl fmt::Display for MapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Heap => write!(f, "Heap"),
            Self::Module => write!(f, "Module"),
            Self::Stack => write!(f, "Stack"),
            Self::Private => write!(f, "Private"),
        }
    }
}

#[cfg(all(feature = "maps", any(target_os = "linux", target_os = "windows")))]
#[derive(Deserialize, Serialize)]
pub struct MapEntry {
    pub region: Region,
    pub flags: MapFlags,
    pub pathname: Option<PathBuf>,
    #[cfg(all(feature = "maps", target_os = "windows"))]
    pub etype: MapType,
}
#[cfg(all(
    not(feature = "color"),
    feature = "maps",
    any(target_os = "linux", target_os = "windows")
))]
impl fmt::Display for MapEntry {
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "windows")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x}->0x{:x} {} {} {}",
            self.region.start,
            self.region.end,
            self.flags,
            match &self.pathname {
                Some(pathname) => pathname.display().to_string(),
                None => "".to_string(),
            },
            self.etype,
        )
    }
}
#[cfg(all(
    feature = "color",
    feature = "maps",
    any(target_os = "linux", target_os = "windows")
))]
impl fmt::Display for MapEntry {
    #[cfg(target_os = "linux")]
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
                    None => String::new().red(),
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
                    None => String::new(),
                }
            )
        }
    }
    #[cfg(target_os = "windows")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.flags.r & self.flags.w & self.flags.x && !self.flags.guard {
            write!(
                f,
                "{} {} {}",
                format!(
                    "0x{:x}->0x{:x} {}",
                    self.region.start, self.region.end, self.flags
                )
                .red(),
                match &self.pathname {
                    Some(pathname) => pathname.display().to_string().red(),
                    None => "".to_string().red(),
                },
                format!("{}", self.etype).red()
            )
        } else {
            write!(
                f,
                "0x{:x}->0x{:x} {} {} {}",
                self.region.start,
                self.region.end,
                self.flags,
                match &self.pathname {
                    Some(pathname) => pathname.display().to_string(),
                    None => "".to_string(),
                },
                self.etype,
            )
        }
    }
}

#[cfg(all(feature = "maps", target_os = "windows"))]
struct WinProcInfo {
    pub pid: u32,
    pub hprocess: HANDLE,
    pub hsnapshot: HANDLE,
}
#[cfg(all(feature = "maps", target_os = "windows"))]
impl WinProcInfo {
    pub fn new(pid: u32, hprocess: HANDLE, hsnapshot: HANDLE) -> Self {
        Self { pid, hprocess, hsnapshot }
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Deserialize, Serialize)]
pub struct Process {
    pub pid: usize,
    pub binary: Binary,
    #[cfg(all(
        feature = "maps",
        any(target_os = "linux", target_os = "windows")
    ))]
    pub maps: Option<Vec<MapEntry>>,
    pub libraries: Option<Vec<Binary>>,
}
impl Process {
    #[cfg(any(not(feature = "maps"), target_os = "macos"))]
    pub fn new(
        pid: usize,
        binary: Binary,
        libraries: Option<Vec<Binary>>,
    ) -> Self {
        Self { pid, binary, libraries }
    }
    #[cfg(all(
        feature = "maps",
        any(target_os = "linux", target_os = "windows")
    ))]
    pub fn new(
        pid: usize,
        binary: Binary,
        libraries: Option<Vec<Binary>>,
    ) -> Self {
        match Process::parse_maps(pid) {
            Ok(maps) => Self { pid, binary, maps: Some(maps), libraries },
            Err(e) => {
                eprintln!(
                    "Failed to parse maps for process with ID {pid}: {e}"
                );
                Self { pid, binary, maps: None, libraries }
            }
        }
    }
    #[cfg(all(feature = "maps", target_os = "linux"))]
    pub fn parse_maps(pid: usize) -> Result<Vec<MapEntry>, Error> {
        let mut maps = Vec::new();
        for line in fs::read_to_string(format!("/proc/{pid}/maps"))?.lines() {
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
            let pathname = Some(split_line.collect::<Vec<&str>>().join(" "))
                .filter(|x| !x.is_empty())
                .map(PathBuf::from);
            maps.push(MapEntry { region, flags, pathname });
        }
        Ok(maps)
    }

    #[cfg(all(feature = "maps", target_os = "windows"))]
    fn parse_maps(pid: usize) -> Result<Vec<MapEntry>, Error> {
        let mut maps: Vec<MapEntry> = Vec::new();
        if let Err(e) = set_debug_privilege() {
            eprintln!("Unable to adjust token privileges. Reason: {}", e);
        };

        #[allow(clippy::cast_possible_truncation)]
        if let Ok(hprocess) = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid as u32,
            )
        } {
            #[allow(clippy::cast_possible_truncation)]
            if let Ok(hsnapshot) = unsafe {
                CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE
                        | TH32CS_SNAPMODULE32
                        | TH32CS_SNAPTHREAD
                        | TH32CS_SNAPHEAPLIST,
                    pid as u32,
                )
            } {
                let proc = WinProcInfo::new(pid as u32, hprocess, hsnapshot);
                if let Err(e) = fetch_modules(&proc, &mut maps) {
                    eprintln!(
                        "Unable to fetch modules for pid {}. Reason: {}",
                        pid, e
                    );
                };
                if let Err(e) = fetch_stacks(&proc, &mut maps) {
                    eprintln!(
                        "Unable to fetch stacks for pid {}. Reason: {}",
                        pid, e
                    );
                };

                if let Err(e) = fetch_heaps(&proc, &mut maps) {
                    eprintln!(
                        "Unable to fetch heaps for pid {}. Reason: {}",
                        pid, e
                    );
                };

                unsafe { CloseHandle(hsnapshot) };
            }
            unsafe { CloseHandle(hprocess) };
        };

        if !maps.is_empty() {
            return Ok(maps);
        }

        Err(Error::last_os_error())
    }
}

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Deserialize, Serialize)]
pub struct Processes {
    pub processes: Vec<Process>,
}
impl Processes {
    pub fn new(processes: Vec<Process>) -> Self {
        Self { processes }
    }
}

#[cfg(all(feature = "maps", target_os = "windows"))]
fn set_debug_privilege() -> Result<(), Error> {
    let mut htoken = HANDLE::default();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut htoken,
        )
    }
    .as_bool()
    {
        let mut luid = LUID::default();
        let wprivstr: Vec<u16> = OsStr::new("SeDebugPrivilege")
            .encode_wide()
            .chain(once(0))
            .collect();
        if unsafe {
            LookupPrivilegeValueW(
                PCWSTR::null(),
                PCWSTR(wprivstr.as_ptr()),
                &mut luid,
            )
        }
        .as_bool()
        {
            let tkp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            #[allow(clippy::cast_possible_truncation)]
            if !unsafe {
                AdjustTokenPrivileges(
                    htoken,
                    false,
                    Some(&tkp),
                    mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    Some(&mut TOKEN_PRIVILEGES::default()),
                    Some(&mut 0_u32),
                )
            }
            .as_bool()
            {
                return Err(Error::last_os_error());
            }
        }
        unsafe { CloseHandle(htoken) };
    } else {
        return Err(Error::last_os_error());
    }

    Ok(())
}

#[cfg(all(feature = "maps", target_os = "windows"))]
fn fetch_modules(
    proc: &WinProcInfo,
    maps: &mut Vec<MapEntry>,
) -> Result<u32, Error> {
    let mut entries = 0_u32;

    let mut lpme = unsafe { mem::zeroed::<MODULEENTRY32W>() };
    #[allow(clippy::cast_possible_truncation)]
    let dw_size = mem::size_of::<MODULEENTRY32W>() as u32;
    lpme.dwSize = dw_size;
    let mut cur_mod = unsafe { Module32FirstW(proc.hsnapshot, &mut lpme) };
    loop {
        if !cur_mod.as_bool() {
            break;
        }

        let region = Region::new(
            lpme.modBaseAddr as usize,
            lpme.modBaseAddr as usize + lpme.modBaseSize as usize,
        );

        let mut lpbuffer =
            unsafe { mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
        let size = mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let retsize = unsafe {
            VirtualQueryEx(
                proc.hprocess,
                Some(region.start as *const c_void),
                &mut lpbuffer,
                size,
            )
        };
        if retsize != size {
            return Err(Error::last_os_error());
        }

        let flags = MapFlags::new(lpbuffer.Protect);

        let mut path = String::from_utf16_lossy(&lpme.szExePath);
        while path.ends_with('\u{0}') {
            path.pop();
        }
        let pathname = Some(PathBuf::from(path));

        maps.push(MapEntry {
            region,
            flags,
            pathname,
            etype: MapType::Module,
        });
        cur_mod = unsafe { Module32NextW(proc.hsnapshot, &mut lpme) };
        entries += 1_u32;
    }
    Ok(entries)
}

#[allow(clippy::similar_names)]
#[cfg(all(feature = "maps", target_os = "windows"))]
fn fetch_heaps(
    proc: &WinProcInfo,
    maps: &mut Vec<MapEntry>,
) -> Result<u32, Error> {
    let mut entries = 0_u32;
    let mut lphl = unsafe { mem::zeroed::<HEAPLIST32>() };
    lphl.dwSize = mem::size_of::<HEAPLIST32>();
    let mut cur_heap = unsafe { Heap32ListFirst(proc.hsnapshot, &mut lphl) };
    if cur_heap.as_bool() {
        loop {
            if !cur_heap.as_bool() {
                break;
            }

            let mut lpbuffer =
                unsafe { mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            let _ = unsafe {
                VirtualQueryEx(
                    proc.hprocess,
                    Some(lphl.th32HeapID as *const std::ffi::c_void),
                    &mut lpbuffer,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            let region = Region::new(
                lphl.th32HeapID,
                lphl.th32HeapID + lpbuffer.RegionSize,
            );

            let mut lphe = unsafe { mem::zeroed::<HEAPENTRY32>() };
            lphe.dwSize = mem::size_of::<HEAPENTRY32>();
            let mut cur_entry = unsafe {
                Heap32First(&mut lphe, lphl.th32ProcessID, lphl.th32HeapID)
            };

            let mut heap_flags = Vec::<MapFlags>::default();
            loop {
                if !cur_entry.as_bool() {
                    break;
                }

                let mut lpbuffer =
                    unsafe { mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
                let size = mem::size_of::<MEMORY_BASIC_INFORMATION>();
                let retsize = unsafe {
                    VirtualQueryEx(
                        proc.hprocess,
                        Some(region.start as *const c_void),
                        &mut lpbuffer,
                        size,
                    )
                };
                if retsize != size {
                    return Err(Error::last_os_error());
                }

                heap_flags.push(MapFlags::new(lpbuffer.Protect));

                cur_entry = unsafe { Heap32Next(&mut lphe) };
                entries += 1_u32;
            }

            maps.push(MapEntry {
                region,
                flags: MapFlags {
                    r: heap_flags.iter().map(|m| m.r).any(|r| r),
                    w: heap_flags.iter().map(|m| m.w).any(|w| w),
                    x: heap_flags.iter().map(|m| m.x).any(|x| x),
                    guard: heap_flags.iter().map(|m| m.guard).any(|g| g),
                },
                pathname: None,
                etype: MapType::Heap,
            });

            cur_heap = unsafe { Heap32ListNext(proc.hsnapshot, &mut lphl) };
        }
    } else {
        return Err(Error::last_os_error());
    }
    Ok(entries)
}

#[allow(clippy::similar_names)]
#[cfg(all(feature = "maps", target_os = "windows"))]
fn fetch_stacks(
    proc: &WinProcInfo,
    maps: &mut Vec<MapEntry>,
) -> Result<u32, Error> {
    let mut entries = 0_u32;
    let mut lpte = unsafe { mem::zeroed::<THREADENTRY32>() };
    #[allow(clippy::cast_possible_truncation)]
    let dw_size = mem::size_of::<THREADENTRY32>() as u32;
    lpte.dwSize = dw_size;
    let mut cur_thread = unsafe { Thread32First(proc.hsnapshot, &mut lpte) };
    if cur_thread.as_bool() {
        loop {
            if !cur_thread.as_bool() {
                break;
            }
            if lpte.th32OwnerProcessID == proc.pid {
                if let Ok(hthread) = unsafe {
                    OpenThread(
                        THREAD_QUERY_INFORMATION
                            | THREAD_GET_CONTEXT
                            | THREAD_SUSPEND_RESUME,
                        false,
                        lpte.th32ThreadID,
                    )
                } {
                    if unsafe { GetCurrentThreadId() } != lpte.th32ThreadID {
                        unsafe {
                            SuspendThread(hthread);
                        }
                    }
                    let mut lpcontext = unsafe { mem::zeroed::<CONTEXT>() };
                    lpcontext.ContextFlags = 1_u32; // CONTEXT_CONTROL
                    let thread_ctx =
                        unsafe { GetThreadContext(hthread, &mut lpcontext) };
                    if thread_ctx.as_bool() {
                        let mut lpbuffer = unsafe {
                            mem::zeroed::<MEMORY_BASIC_INFORMATION>()
                        };
                        #[cfg(target_arch = "x86_64")]
                        let sp = lpcontext.Rsp;
                        #[cfg(target_arch = "x86")]
                        let sp = lpcontext.Esp;
                        #[cfg(target_arch = "aarch64")]
                        let sp = lpcontext.Sp;

                        let _ = unsafe {
                            VirtualQueryEx(
                                proc.hprocess,
                                Some(sp as *const c_void),
                                &mut lpbuffer,
                                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            )
                        };

                        let region = Region::new(
                            lpbuffer.AllocationBase as usize,
                            lpbuffer.AllocationBase as usize
                                + lpbuffer.RegionSize,
                        );

                        let flags = MapFlags::new(lpbuffer.Protect);

                        maps.push(MapEntry {
                            region,
                            flags,
                            pathname: None,
                            etype: MapType::Stack,
                        });

                        if unsafe { GetCurrentThreadId() } != lpte.th32ThreadID
                        {
                            unsafe {
                                ResumeThread(hthread);
                            }
                        }
                        entries += 1_u32;
                    } else {
                        return Err(Error::last_os_error());
                    }
                } else {
                    return Err(Error::last_os_error());
                }
            }
            cur_thread = unsafe { Thread32Next(proc.hsnapshot, &mut lpte) };
        }
    } else {
        return Err(Error::last_os_error());
    }
    Ok(entries)
}
