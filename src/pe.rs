use colored::*;
use goblin::pe::utils::get_data;
use goblin::pe::PE;
use memmap::Mmap;
use scroll_derive::Pread;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::shared::colorize_bool;

const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

// stored in IMAGE_LOAD_CONFIG_DIRECTORY64
const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Pread)]
pub struct ImageLoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalogoffset: u32,
    reserved: u32,
}
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory32
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Pread)]
pub struct ImageLoadConfigDirectory32 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    decommit_free_block_threshold: u32,
    decommit_total_free_threshold: u32,
    lock_prefix_table: u32,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    depedent_load_flags: u16,
    edit_list: u32,
    security_cookie: u32,
    sehandler_table: u32,
    sehandler_count: u32,
    guard_cf_check_function_pointer: u32,
    guard_cf_dispatch_function_pointer: u32,
    guard_cf_function_table: u32,
    guard_cf_function_count: u32,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u32,
    guard_address_taken_iat_entry_count: u32,
    guard_long_jump_target_table: u32,
    guard_long_jump_target_count: u32,
    dynamic_value_reloc_table: u32,
    ch_pe_metadata_pointer: u32,
    guard_rf_failure_routine: u32,
    guard_rf_failure_routine_function_pointer: u32,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u32,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u32,
    volatiile_metadata_pointer: u32,
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Pread)]
pub struct ImageLoadConfigDirectory64 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    decommit_free_block_threshold: u64,
    decommit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    depedent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    sehandler_table: u64,
    sehandler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u64,
    guard_address_taken_iat_entry_count: u64,
    guard_long_jump_target_table: u64,
    guard_long_jump_target_count: u64,
    dynamic_value_reloc_table: u64,
    ch_pe_metadata_pointer: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_function_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u64,
    volatiile_metadata_pointer: u64,
}

// Unified 32/64-bit IMAGE_LOAD_CONFIG_DIRECTORY fields
type ImageLoadConfigDirectory = ImageLoadConfigDirectory64;
impl From<ImageLoadConfigDirectory32> for ImageLoadConfigDirectory {
    fn from(cfg: ImageLoadConfigDirectory32) -> Self {
        ImageLoadConfigDirectory {
            size: cfg.size,
            time_date_stamp: cfg.time_date_stamp,
            major_version: cfg.major_version,
            minor_version: cfg.minor_version,
            global_flags_clear: cfg.global_flags_clear,
            global_flags_set: cfg.global_flags_set,
            critical_section_default_timeout: cfg
                .critical_section_default_timeout,
            decommit_free_block_threshold: cfg.decommit_free_block_threshold
                as u64,
            decommit_total_free_threshold: cfg.decommit_total_free_threshold
                as u64,
            lock_prefix_table: cfg.lock_prefix_table as u64,
            maximum_allocation_size: cfg.maximum_allocation_size as u64,
            virtual_memory_threshold: cfg.virtual_memory_threshold as u64,
            process_affinity_mask: cfg.process_affinity_mask as u64,
            process_heap_flags: cfg.process_heap_flags,
            csd_version: cfg.csd_version,
            depedent_load_flags: cfg.depedent_load_flags,
            edit_list: cfg.edit_list as u64,
            security_cookie: cfg.security_cookie as u64,
            sehandler_table: cfg.sehandler_table as u64,
            sehandler_count: cfg.sehandler_count as u64,
            guard_cf_check_function_pointer: cfg
                .guard_cf_check_function_pointer
                as u64,
            guard_cf_dispatch_function_pointer: cfg
                .guard_cf_dispatch_function_pointer
                as u64,
            guard_cf_function_table: cfg.guard_cf_function_table as u64,
            guard_cf_function_count: cfg.guard_cf_function_count as u64,
            guard_flags: cfg.guard_flags,
            code_integrity: cfg.code_integrity,
            guard_address_taken_iat_entry_table: cfg
                .guard_address_taken_iat_entry_table
                as u64,
            guard_address_taken_iat_entry_count: cfg
                .guard_address_taken_iat_entry_count
                as u64,
            guard_long_jump_target_table: cfg.guard_long_jump_target_table
                as u64,
            guard_long_jump_target_count: cfg.guard_long_jump_target_count
                as u64,
            dynamic_value_reloc_table: cfg.dynamic_value_reloc_table as u64,
            ch_pe_metadata_pointer: cfg.ch_pe_metadata_pointer as u64,
            guard_rf_failure_routine: cfg.guard_rf_failure_routine as u64,
            guard_rf_failure_routine_function_pointer: cfg
                .guard_rf_failure_routine_function_pointer
                as u64,
            dynamic_value_reloc_table_offset: cfg
                .dynamic_value_reloc_table_offset,
            dynamic_value_reloc_table_section: cfg
                .dynamic_value_reloc_table_section,
            reserved2: cfg.reserved2,
            guard_rf_verify_stack_pointer_function_pointer: cfg
                .guard_rf_verify_stack_pointer_function_pointer
                as u64,
            hot_patch_table_offset: cfg.hot_patch_table_offset,
            reserved3: cfg.reserved3,
            enclave_configuration_pointer: cfg.enclave_configuration_pointer
                as u64,
            volatiile_metadata_pointer: cfg.volatiile_metadata_pointer as u64,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub enum ASLR {
    None,
    DynamicBase,
    HighEntropyVa,
}
impl fmt::Display for ASLR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ASLR::None => write!(f, "{}", "None".red()),
            ASLR::DynamicBase => write!(f, "{}", "DYNBASE".yellow()),
            ASLR::HighEntropyVa => {
                write!(f, "{}", "HIGHENTROPYVA".bright_green())
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PECheckSecResults {
    aslr: ASLR,
    authenticode: bool,
    cfg: bool,
    clr: bool,
    dep: bool,
    dynamic_base: bool,
    force_integrity: bool,
    gs: bool,
    high_entropy_va: bool,
    isolation: bool,
    rfg: bool,
    safeseh: bool,
    seh: bool,
}

impl PECheckSecResults {
    pub fn parse(pe: &PE, buffer: &Mmap) -> PECheckSecResults {
        PECheckSecResults {
            aslr: pe.has_aslr(),
            authenticode: pe.has_authenticode(buffer),
            cfg: pe.has_cfg(),
            clr: pe.has_clr(),
            dep: pe.has_dep(),
            dynamic_base: pe.has_dynamic_base(),
            force_integrity: pe.has_force_integrity(),
            gs: pe.has_gs(buffer),
            high_entropy_va: pe.has_high_entropy_va(),
            isolation: pe.has_isolation(),
            rfg: pe.has_rfg(buffer),
            safeseh: pe.has_safe_seh(buffer),
            seh: pe.has_seh(),
        }
    }
}
impl fmt::Display for PECheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} \
             {} {} {} {} {} {} {} {} {} {} {} {}",
            "ASLR:".bold(),
            self.aslr,
            "Authenticode:".bold(),
            colorize_bool(self.authenticode),
            "CFG:".bold(),
            colorize_bool(self.cfg),
            "CLR:".bold(),
            colorize_bool(self.clr),
            "DEP:".bold(),
            colorize_bool(self.dep),
            "Dynamic Base:".bold(),
            colorize_bool(self.dynamic_base),
            "Force Integrity:".bold(),
            colorize_bool(self.force_integrity),
            "GS:".bold(),
            colorize_bool(self.gs),
            "High Entropy VA:".bold(),
            colorize_bool(self.high_entropy_va),
            "Isolation:".bold(),
            colorize_bool(self.isolation),
            "RFG:".bold(),
            colorize_bool(self.rfg),
            "SafeSEH:".bold(),
            colorize_bool(self.safeseh),
            "SEH:".bold(),
            colorize_bool(self.seh)
        )
    }
}

pub trait PEProperties {
    fn has_aslr(&self) -> ASLR;
    fn has_authenticode(&self, mem: &memmap::Mmap) -> bool;
    fn has_cfg(&self) -> bool;
    fn has_clr(&self) -> bool;
    fn has_dep(&self) -> bool;
    fn has_dynamic_base(&self) -> bool;
    fn has_force_integrity(&self) -> bool;
    fn has_gs(&self, mem: &memmap::Mmap) -> bool;
    fn has_high_entropy_va(&self) -> bool;
    fn has_isolation(&self) -> bool;
    fn has_rfg(&self, mem: &memmap::Mmap) -> bool;
    fn has_safe_seh(&self, mem: &memmap::Mmap) -> bool;
    fn has_seh(&self) -> bool;
}

impl PEProperties for PE<'_> {
    fn has_aslr(&self) -> ASLR {
        if self.has_dynamic_base() & self.has_high_entropy_va() {
            return ASLR::HighEntropyVa;
        } else if self.has_dynamic_base() {
            return ASLR::DynamicBase;
        }
        ASLR::None
    }
    fn has_authenticode(&self, mem: &memmap::Mmap) -> bool {
        // requires running platform to be Windows for verification
        // just check for existence right now
        if let Some(optional_header) = self.header.optional_header {
            let file_alignment = optional_header.windows_fields.file_alignment;
            let sections = &self.sections;
            if let Some(load_config_hdr) =
                optional_header.data_directories.get_load_config_table()
            {
                let load_config_val: ImageLoadConfigDirectory =
                    get_data(mem, sections, *load_config_hdr, file_alignment)
                        .unwrap();
                return load_config_val.code_integrity.flags != 0;
            }
        }
        false
    }
    fn has_cfg(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(
                dllcharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                x if x != 0
            );
        }
        false
    }
    fn has_clr(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            if optional_header
                .data_directories
                .get_clr_runtime_header()
                .is_some()
            {
                return true;
            }
        }
        false
    }
    fn has_dep(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(
                dllcharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                    x if x != 0
            );
        }
        false
    }
    fn has_dynamic_base(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(
                dllcharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                x if x != 0
            );
        }
        false
    }
    fn has_force_integrity(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(
                dllcharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
                x if x != 0
            );
        }
        false
    }
    fn has_gs(&self, mem: &memmap::Mmap) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let file_alignment = optional_header.windows_fields.file_alignment;
            let sections = &self.sections;
            if let Some(load_config_hdr) =
                optional_header.data_directories.get_load_config_table()
            {
                let load_config_val: ImageLoadConfigDirectory =
                    get_data(mem, sections, *load_config_hdr, file_alignment)
                        .unwrap();
                return load_config_val.security_cookie != 0;
            }
        }
        false
    }
    fn has_high_entropy_va(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(dllcharacteristics & 0x20, x if x != 0);
        }
        false
    }
    fn has_isolation(&self) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let dllcharacteristics: u16 =
                optional_header.windows_fields.dll_characteristics;
            return matches!(
                dllcharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
                x if x == 0
            );
        }
        false
    }
    fn has_rfg(&self, mem: &memmap::Mmap) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let file_alignment = optional_header.windows_fields.file_alignment;
            let sections = &self.sections;
            if let Some(load_config_hdr) =
                optional_header.data_directories.get_load_config_table()
            {
                let load_config_val: ImageLoadConfigDirectory =
                    get_data(mem, sections, *load_config_hdr, file_alignment)
                        .unwrap();
                let guard_flags = load_config_val.guard_flags;
                if (guard_flags & IMAGE_GUARD_RF_INSTRUMENTED) != 0
                    && (guard_flags & IMAGE_GUARD_RF_ENABLE) != 0
                    || (guard_flags & IMAGE_GUARD_RF_STRICT) != 0
                {
                    return true;
                }
            }
        }
        false
    }
    fn has_safe_seh(&self, mem: &memmap::Mmap) -> bool {
        if let Some(optional_header) = self.header.optional_header {
            let file_alignment = optional_header.windows_fields.file_alignment;
            let sections = &self.sections;
            if let Some(load_config_hdr) =
                optional_header.data_directories.get_load_config_table()
            {
                let load_config_val: ImageLoadConfigDirectory =
                    get_data(mem, sections, *load_config_hdr, file_alignment)
                        .unwrap();
                return load_config_val.sehandler_count != 0;
            }
        }
        false
    }
    fn has_seh(&self) -> bool {
        match self.header.optional_header {
            Some(optional_header) => {
                let dllcharacteristics: u16 =
                    optional_header.windows_fields.dll_characteristics;
                matches!(
                    dllcharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH,
                    x if x == 0
                )
            }
            _ => false,
        }
    }
}
