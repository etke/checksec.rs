#[cfg(feature = "disassembly")]
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

#[cfg(feature = "disassembly")]
#[derive(Clone, Copy, PartialEq)]
pub enum Bitness {
    B64,
    B32,
}

#[cfg(feature = "disassembly")]
impl Bitness {
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self {
            Self::B64 => 64,
            Self::B32 => 32,
        }
    }
}

#[cfg(feature = "disassembly")]
#[derive(PartialEq)]
enum SCPSteps {
    Init,
    StartCmp,
    StartJump,
    CheckSubFirst,
    CheckOr,
    CheckSubLast,
    CheckXor,
    EndCmp,
}

#[cfg(feature = "disassembly")]
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn has_stack_clash_protection(
    bytes: &[u8],
    bitness: Bitness,
    rip: u64,
) -> bool {
    let mut decoder =
        Decoder::with_ip(bitness.as_u32(), bytes, rip, DecoderOptions::NONE);

    let mut instr = Instruction::default();

    let mut step = SCPSteps::Init;
    let mut start_addr = 0;
    let mut check_addr = 0;
    let mut jump_addr = 0;

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);

        /*
        GCC:
        109e:       cmp    rsp,rcx
        10a1:       je     10b8 <main+0x68>
        10a3:       sub    rsp,0x1000
        10aa:       or     QWORD PTR [rsp+0xff8],0x0
        10b3:       cmp    rsp,rcx
        10b6:       jne    10a3 <main+0x53>
        10b8:

        109e:	    cmp    rsp,rcx
        10a1:   	je     10b5 <main+0x65>
        10a3:	    sub    rsp,0x1000
        10aa:	    or     QWORD PTR [rsp+0xff8],0x0
        10b3:	    jmp    109e <main+0x4e>
        10b5:

        Clang:
        118b:       cmp    rbx,rsp
        118e:       jge    11a1 <main+0x61>
        1190:       xor    QWORD PTR [rsp],0x0
        1195:       sub    rsp,0x1000
        119c:       cmp    rbx,rsp
        119f:       jl     1190 <main+0x50>
        11a1:

        1187:	    cmp    rbx,rsp
        118a:	    jge    119a <main+0x5e>
        118c:	    xor    QWORD PTR [rsp],0x0
        1191:	    sub    rsp,0x1000
        1198:	    jmp    1187 <main+0x4b>
        119a:
        */

        let mnemonic = instr.mnemonic();

        if step == SCPSteps::Init
            && mnemonic == Mnemonic::Cmp
            && (is_stack_pointer(instr.op0_register(), bitness)
                || is_stack_pointer(instr.op1_register(), bitness))
        {
            step = SCPSteps::StartCmp;
            start_addr = instr.ip();
            continue;
        } else if step == SCPSteps::StartCmp
            && (mnemonic == Mnemonic::Je || mnemonic == Mnemonic::Jge)
        {
            step = SCPSteps::StartJump;
            jump_addr = if bitness == Bitness::B64 {
                instr.memory_displacement64()
            } else {
                u64::from(instr.memory_displacement32())
            };
            continue;
        } else if step == SCPSteps::StartJump
            && mnemonic == Mnemonic::Sub
            && is_stack_pointer(instr.op0_register(), bitness)
            && instr.immediate(1) == 4096
        {
            step = SCPSteps::CheckSubFirst;
            if check_addr == 0 {
                check_addr = instr.ip();
            }
            continue;
        } else if step == SCPSteps::CheckSubFirst
            && mnemonic == Mnemonic::Or
            && is_stack_pointer(instr.memory_base(), bitness)
            && instr.immediate(1) == 0
        {
            step = SCPSteps::CheckOr;
            if check_addr == 0 {
                check_addr = instr.ip();
            }
            continue;
        } else if step == SCPSteps::StartJump
            && mnemonic == Mnemonic::Xor
            && is_stack_pointer(instr.memory_base(), bitness)
            && instr.immediate(1) == 0
        {
            step = SCPSteps::CheckXor;
            if check_addr == 0 {
                check_addr = instr.ip();
            }
            continue;
        } else if step == SCPSteps::CheckXor
            && mnemonic == Mnemonic::Sub
            && is_stack_pointer(instr.op0_register(), bitness)
            && instr.immediate(1) == 4096
        {
            step = SCPSteps::CheckSubLast;
            continue;
        } else if (step == SCPSteps::CheckOr || step == SCPSteps::CheckSubLast)
            && mnemonic == Mnemonic::Jmp
        {
            let mem_disp = if bitness == Bitness::B64 {
                instr.memory_displacement64()
            } else {
                u64::from(instr.memory_displacement32())
            };
            if mem_disp == start_addr && jump_addr == instr.next_ip() {
                return true;
            }
        } else if (step == SCPSteps::CheckOr || step == SCPSteps::CheckSubLast)
            && mnemonic == Mnemonic::Cmp
            && (is_stack_pointer(instr.op0_register(), bitness)
                || is_stack_pointer(instr.op1_register(), bitness))
        {
            step = SCPSteps::EndCmp;
            continue;
        } else if step == SCPSteps::EndCmp
            && (mnemonic == Mnemonic::Jne || mnemonic == Mnemonic::Jl)
        {
            let mem_disp = if bitness == Bitness::B64 {
                instr.memory_displacement64()
            } else {
                u64::from(instr.memory_displacement32())
            };
            if mem_disp == check_addr && jump_addr == instr.next_ip() {
                return true;
            }
        }

        step = SCPSteps::Init;
        start_addr = 0;
        check_addr = 0;
        jump_addr = 0;
    }

    false
}

#[cfg(feature = "disassembly")]
fn is_stack_pointer(reg: iced_x86::Register, bitness: Bitness) -> bool {
    reg == match bitness {
        Bitness::B64 => iced_x86::Register::RSP,
        Bitness::B32 => iced_x86::Register::ESP,
    }
}
