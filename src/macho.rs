use colored::*;
use goblin;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::shared::colorize_bool;
//use crate::shared::{colorize_bool, Rpath, VecRpath};

const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

#[derive(Debug, Deserialize, Serialize)]
pub struct MachOCheckSecResults {
    arc: bool,
    canary: bool,
    code_signature: bool,
    encrypted: bool,
    nx_heap: bool,
    nx_stack: bool,
    pie: bool,
    restrict: bool,
    //rpath: VecRpath,
    rpath: bool,
}

impl MachOCheckSecResults {
    pub fn parse(macho: &MachO) -> MachOCheckSecResults {
        MachOCheckSecResults {
            arc: macho.has_arc(),
            canary: macho.has_canary(),
            code_signature: macho.has_code_signature(),
            encrypted: macho.has_encrypted(),
            nx_heap: macho.has_nx_heap(),
            nx_stack: macho.has_nx_stack(),
            pie: macho.has_pie(),
            restrict: macho.has_restrict(),
            rpath: macho.has_rpath(),
        }
    }
}
impl fmt::Display for MachOCheckSecResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            "ARC:".bold(),
            colorize_bool(self.arc),
            "Canary:".bold(),
            colorize_bool(self.canary),
            "Code Signature:".bold(),
            colorize_bool(self.code_signature),
            "Encrypted:".bold(),
            colorize_bool(self.encrypted),
            "NX Heap:".bold(),
            colorize_bool(self.nx_heap),
            "NX Stack:".bold(),
            colorize_bool(self.nx_stack),
            "PIE:".bold(),
            colorize_bool(self.pie),
            "Restrict:".bold(),
            colorize_bool(self.restrict),
            "RPath:".bold(),
            //self.rpath
            colorize_bool(self.rpath)
        )
    }
}

pub trait MachOProperties {
    fn has_arc(&self) -> bool;
    fn has_canary(&self) -> bool;
    fn has_code_signature(&self) -> bool;
    fn has_encrypted(&self) -> bool;
    fn has_nx_heap(&self) -> bool;
    fn has_nx_stack(&self) -> bool;
    fn has_pie(&self) -> bool;
    fn has_restrict(&self) -> bool;
    //fn has_rpath(&self) -> VecRpath;
    fn has_rpath(&self) -> bool;
}
impl MachOProperties for MachO<'_> {
    fn has_arc(&self) -> bool {
        if let Ok(imports) = self.imports() {
            for import in imports.iter() {
                if import.name == "_objc_release" {
                    return true;
                }
            }
        }
        false
    }
    fn has_canary(&self) -> bool {
        if let Ok(imports) = self.imports() {
            for import in imports.iter() {
                match import.name {
                    "___stack_chk_fail" => return true,
                    "___stack_chk_guard" => return true,
                    _ => continue,
                }
            }
        }
        false
    }
    fn has_code_signature(&self) -> bool {
        for loadcmd in self.load_commands.iter() {
            match loadcmd.command {
                CommandVariant::CodeSignature(cmd) => {
                    // just check for existence, todo full validation
                    if cmd.datasize > 0 {
                        return true;
                    }
                }
                _ => (),
            }
        }
        false
    }
    fn has_encrypted(&self) -> bool {
        for loadcmd in self.load_commands.iter() {
            match loadcmd.command {
                CommandVariant::EncryptionInfo32(cmd) => {
                    if cmd.cryptid != 0 {
                        return true;
                    }
                }
                CommandVariant::EncryptionInfo64(cmd) => {
                    if cmd.cryptid != 0 {
                        return true;
                    }
                }
                _ => (),
            }
        }
        false
    }
    fn has_nx_heap(&self) -> bool {
        matches!(self.header.flags & MH_NO_HEAP_EXECUTION, x if x != 0)
    }
    fn has_nx_stack(&self) -> bool {
        !matches!(self.header.flags & MH_ALLOW_STACK_EXECUTION, x if x != 0)
    }
    fn has_pie(&self) -> bool {
        matches!(self.header.flags & MH_PIE, x if x != 0)
    }
    fn has_restrict(&self) -> bool {
        for segment in self.segments.iter() {
            if let Ok(name) = segment.name() {
                if name.to_string().to_lowercase() == "__restrict" {
                    return true;
                }
            }
        }
        false
    }
    //fn has_rpath(&self) -> VecRpath {
    fn has_rpath(&self) -> bool {
        // simply check for existence of @rpath command for now
        // parse out rpath entries similar to elf later
        // paths separated by `;` instead of `:` like the elf counterpart
        for loadcmd in self.load_commands.iter() {
            if let CommandVariant::Rpath(_) = loadcmd.command {
                return true;
                //return VecRpath::new(vec![Rpath::Yes("true".to_string())]);
            }
        }
        //VecRpath::new(vec![Rpath::None])
        false
    }
}
