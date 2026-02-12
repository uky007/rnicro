//! One-gadget / magic gadget finder.
//!
//! Finds code addresses in libc that call `execve("/bin/sh", NULL, NULL)`
//! with minimal constraints, modeled after david942j's one_gadget tool.

use crate::error::{Error, Result};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, OpKind, Register};

/// A one-gadget candidate.
#[derive(Debug, Clone)]
pub struct OneGadget {
    /// Offset from the base of the ELF (add to leaked base for runtime address).
    pub offset: u64,
    /// Constraints that must be satisfied.
    pub constraints: Vec<Constraint>,
    /// Difficulty rating based on constraint count.
    pub difficulty: Difficulty,
    /// Disassembly of the gadget region.
    pub disassembly: String,
}

/// A constraint that must hold for a one-gadget to work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// Register must be NULL (0).
    RegNull(ConstraintReg),
    /// Stack slot at [rsp + offset] must be NULL.
    StackNull(i64),
    /// RSP must be 16-byte aligned.
    RspAligned,
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegNull(reg) => write!(f, "{} == NULL", reg),
            Self::StackNull(off) => write!(f, "[rsp+{:#x}] == NULL", off),
            Self::RspAligned => write!(f, "rsp & 0xf == 0"),
        }
    }
}

/// Registers referenced in constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintReg {
    Rax, Rbx, Rcx, Rdx, Rsi, Rdi, R12, R15,
}

impl std::fmt::Display for ConstraintReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rax => "rax", Self::Rbx => "rbx", Self::Rcx => "rcx",
            Self::Rdx => "rdx", Self::Rsi => "rsi", Self::Rdi => "rdi",
            Self::R12 => "r12", Self::R15 => "r15",
        };
        write!(f, "{}", s)
    }
}

/// Difficulty rating for a one-gadget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Difficulty {
    /// No constraints beyond jumping here.
    Easy,
    /// 1-2 simple constraints (stack alignment, one register zeroed).
    Medium,
    /// Multiple constraints or stack slot requirements.
    Hard,
}

impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Easy => write!(f, "easy"),
            Self::Medium => write!(f, "medium"),
            Self::Hard => write!(f, "hard"),
        }
    }
}

/// Symbolic register value during forward analysis.
#[derive(Debug, Clone, PartialEq)]
enum SymValue {
    /// A known constant.
    Constant(u64),
    /// Address of a "/bin/sh" string.
    BinShAddr,
    /// Value loaded from [rsp + offset].
    StackSlot(i64),
}

/// Find one-gadgets in an ELF binary (typically libc).
pub fn find_one_gadgets(data: &[u8]) -> Result<Vec<OneGadget>> {
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    // Step 1: Find "/bin/sh\0" string
    let binsh_offsets = find_binsh_strings(data);
    if binsh_offsets.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Find execve symbol address (from .dynsym or .symtab)
    let execve_addr = find_symbol_addr(&elf, "execve");

    // Step 3: Locate .text section for scanning
    let text_section = elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text"
    });

    let (text_offset, text_size, text_vaddr) = match text_section {
        Some(sh) => (sh.sh_offset as usize, sh.sh_size as usize, sh.sh_addr),
        None => return Ok(Vec::new()),
    };

    if text_offset + text_size > data.len() {
        return Ok(Vec::new());
    }

    let text_data = &data[text_offset..text_offset + text_size];

    // Step 4: Find execve call sites and syscall sites
    let mut gadgets = Vec::new();

    // Scan for `call execve` sites (E8 rel32)
    if let Some(execve_va) = execve_addr {
        for i in 0..text_data.len().saturating_sub(4) {
            if text_data[i] == 0xE8 {
                let rel = i32::from_le_bytes(text_data[i+1..i+5].try_into().unwrap());
                let call_va = text_vaddr + i as u64;
                let target = (call_va as i64 + 5 + rel as i64) as u64;
                if target == execve_va {
                    if let Some(g) = analyze_call_site(
                        text_data, text_vaddr, i, &binsh_offsets, data,
                    ) {
                        gadgets.push(g);
                    }
                }
            }
        }
    }

    // Scan for `syscall` instructions preceded by `mov eax, 59`
    for i in 0..text_data.len().saturating_sub(1) {
        if text_data[i] == 0x0F && text_data[i + 1] == 0x05 {
            if let Some(g) = analyze_syscall_site(
                text_data, text_vaddr, i, &binsh_offsets, data,
            ) {
                gadgets.push(g);
            }
        }
    }

    // Sort by difficulty
    gadgets.sort_by_key(|g| g.difficulty);
    Ok(gadgets)
}

/// Find all offsets of "/bin/sh\0" in the binary data.
pub fn find_binsh_strings(data: &[u8]) -> Vec<u64> {
    let needle = b"/bin/sh\0";
    let mut offsets = Vec::new();
    for i in 0..data.len().saturating_sub(needle.len()) {
        if &data[i..i + needle.len()] == needle {
            offsets.push(i as u64);
        }
    }
    offsets
}

/// Find a symbol's virtual address in the ELF.
fn find_symbol_addr(elf: &goblin::elf::Elf, name: &str) -> Option<u64> {
    for sym in &elf.dynsyms {
        if sym.st_value != 0 {
            if let Some(n) = elf.dynstrtab.get_at(sym.st_name) {
                if n == name {
                    return Some(sym.st_value);
                }
            }
        }
    }
    for sym in &elf.syms {
        if sym.st_value != 0 {
            if let Some(n) = elf.strtab.get_at(sym.st_name) {
                if n == name {
                    return Some(sym.st_value);
                }
            }
        }
    }
    None
}

/// Analyze a `call execve` site by backtracking to find entry points.
fn analyze_call_site(
    text_data: &[u8],
    text_vaddr: u64,
    call_offset: usize,
    binsh_offsets: &[u64],
    elf_data: &[u8],
) -> Option<OneGadget> {
    // Backtrack up to 40 bytes to find a potential entry point
    let max_back = 40.min(call_offset);

    for back in 4..=max_back {
        let start = call_offset - back;
        let candidate_va = text_vaddr + start as u64;
        let region = &text_data[start..call_offset + 5]; // include the call

        if let Some(gadget) = try_analyze_forward(
            region, candidate_va, binsh_offsets, elf_data, call_offset - start,
        ) {
            return Some(gadget);
        }
    }
    None
}

/// Analyze a `syscall` site for rax=59 setup.
fn analyze_syscall_site(
    text_data: &[u8],
    text_vaddr: u64,
    syscall_offset: usize,
    binsh_offsets: &[u64],
    elf_data: &[u8],
) -> Option<OneGadget> {
    let max_back = 40.min(syscall_offset);

    for back in 4..=max_back {
        let start = syscall_offset - back;
        let candidate_va = text_vaddr + start as u64;
        let region = &text_data[start..syscall_offset + 2]; // include syscall

        // Forward-analyze to check if rax gets set to 59
        let mut decoder = Decoder::with_ip(64, region, candidate_va, DecoderOptions::NONE);
        let mut regs: std::collections::HashMap<Register, SymValue> = std::collections::HashMap::new();
        let mut valid = true;

        while decoder.can_decode() {
            let insn = decoder.decode();
            if insn.is_invalid() {
                valid = false;
                break;
            }
            update_reg_state(&insn, &mut regs, binsh_offsets, elf_data);

            if insn.code() == Code::Syscall {
                break;
            }
            // Stop if we hit a branch or call
            match insn.flow_control() {
                FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Return => {
                    valid = false;
                    break;
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    // Allow call (might be call execve variant)
                    break;
                }
                _ => {}
            }
        }

        if !valid {
            continue;
        }

        // Check if rax == 59
        let rax_is_execve = matches!(
            regs.get(&Register::RAX).or(regs.get(&Register::EAX)),
            Some(SymValue::Constant(59))
        );
        let rdi_is_binsh = matches!(
            regs.get(&Register::RDI),
            Some(SymValue::BinShAddr)
        );

        if rax_is_execve && rdi_is_binsh {
            let mut constraints = Vec::new();
            check_constraint(&regs, Register::RSI, &mut constraints);
            check_constraint(&regs, Register::RDX, &mut constraints);

            let difficulty = match constraints.len() {
                0 => Difficulty::Easy,
                1..=2 => Difficulty::Medium,
                _ => Difficulty::Hard,
            };

            return Some(OneGadget {
                offset: candidate_va,
                constraints,
                difficulty,
                disassembly: format_region(region, candidate_va),
            });
        }
    }
    None
}

/// Forward-analyze a code region to check for execve pattern.
fn try_analyze_forward(
    region: &[u8],
    base_va: u64,
    binsh_offsets: &[u64],
    elf_data: &[u8],
    call_rel_offset: usize,
) -> Option<OneGadget> {
    let mut decoder = Decoder::with_ip(64, region, base_va, DecoderOptions::NONE);
    let mut regs: std::collections::HashMap<Register, SymValue> = std::collections::HashMap::new();

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            return None;
        }

        // Stop conditions
        match insn.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Return => {
                return None;
            }
            _ => {}
        }

        update_reg_state(&insn, &mut regs, binsh_offsets, elf_data);

        // Reached the call instruction
        let insn_offset = (insn.ip() - base_va) as usize;
        if insn_offset >= call_rel_offset {
            break;
        }
    }

    // Check if rdi points to /bin/sh
    let rdi_is_binsh = matches!(regs.get(&Register::RDI), Some(SymValue::BinShAddr));
    if !rdi_is_binsh {
        return None;
    }

    let mut constraints = Vec::new();
    check_constraint(&regs, Register::RSI, &mut constraints);
    check_constraint(&regs, Register::RDX, &mut constraints);

    let difficulty = match constraints.len() {
        0 => Difficulty::Easy,
        1..=2 => Difficulty::Medium,
        _ => Difficulty::Hard,
    };

    Some(OneGadget {
        offset: base_va,
        constraints,
        difficulty,
        disassembly: format_region(region, base_va),
    })
}

/// Update register state from a single instruction.
fn update_reg_state(
    insn: &Instruction,
    regs: &mut std::collections::HashMap<Register, SymValue>,
    binsh_offsets: &[u64],
    elf_data: &[u8],
) {
    match insn.code() {
        // xor reg, reg -> zero
        Code::Xor_r32_rm32 | Code::Xor_r64_rm64
        | Code::Xor_rm32_r32 | Code::Xor_rm64_r64 => {
            if insn.op0_register() == insn.op1_register() {
                let reg64 = to_reg64(insn.op0_register());
                regs.insert(reg64, SymValue::Constant(0));
            }
        }
        // mov reg, imm
        Code::Mov_r32_imm32 | Code::Mov_r64_imm64 => {
            let reg64 = to_reg64(insn.op0_register());
            if insn.op1_kind() == OpKind::Immediate32 || insn.op1_kind() == OpKind::Immediate64
                || insn.op1_kind() == OpKind::Immediate32to64
            {
                regs.insert(reg64, SymValue::Constant(insn.immediate(1) as u64));
            }
        }
        // lea reg, [rip + disp]
        Code::Lea_r64_m | Code::Lea_r32_m => {
            if insn.memory_base() == Register::RIP {
                let target = insn.ip().wrapping_add(insn.len() as u64)
                    .wrapping_add(insn.memory_displacement64());
                let reg64 = to_reg64(insn.op0_register());
                // Check if target points to "/bin/sh"
                if binsh_offsets.contains(&target) {
                    regs.insert(reg64, SymValue::BinShAddr);
                } else {
                    // Check if it's within the ELF and points to "/bin/sh" via virtual address mapping
                    // For simplicity, check the raw data at that offset if it's a valid file offset
                    if (target as usize) + 8 <= elf_data.len() {
                        if &elf_data[target as usize..(target as usize) + 8] == b"/bin/sh\0" {
                            regs.insert(reg64, SymValue::BinShAddr);
                        } else {
                            regs.insert(reg64, SymValue::Constant(target));
                        }
                    } else {
                        regs.insert(reg64, SymValue::Constant(target));
                    }
                }
            }
        }
        // mov reg, [rsp + disp]
        Code::Mov_r64_rm64 => {
            if insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RSP {
                let disp = insn.memory_displacement64() as i64;
                let reg64 = to_reg64(insn.op0_register());
                regs.insert(reg64, SymValue::StackSlot(disp));
            } else if insn.op1_kind() == OpKind::Register {
                // mov reg, reg
                let src = to_reg64(insn.op1_register());
                let dst = to_reg64(insn.op0_register());
                if let Some(val) = regs.get(&src).cloned() {
                    regs.insert(dst, val);
                }
            }
        }
        _ => {}
    }
}

/// Check if a register is zero or stack-loaded (generates constraint).
fn check_constraint(
    regs: &std::collections::HashMap<Register, SymValue>,
    reg: Register,
    constraints: &mut Vec<Constraint>,
) {
    match regs.get(&reg) {
        Some(SymValue::Constant(0)) => {} // Already zero, no constraint
        Some(SymValue::StackSlot(offset)) => {
            constraints.push(Constraint::StackNull(*offset));
        }
        None => {
            // Need this register to be zero — add constraint
            if let Some(creg) = to_constraint_reg(reg) {
                constraints.push(Constraint::RegNull(creg));
            }
        }
        _ => {
            if let Some(creg) = to_constraint_reg(reg) {
                constraints.push(Constraint::RegNull(creg));
            }
        }
    }
}

fn to_reg64(reg: Register) -> Register {
    match reg {
        Register::EAX => Register::RAX,
        Register::EBX => Register::RBX,
        Register::ECX => Register::RCX,
        Register::EDX => Register::RDX,
        Register::ESI => Register::RSI,
        Register::EDI => Register::RDI,
        Register::EBP => Register::RBP,
        Register::ESP => Register::RSP,
        Register::R8D => Register::R8,
        Register::R9D => Register::R9,
        Register::R10D => Register::R10,
        Register::R11D => Register::R11,
        Register::R12D => Register::R12,
        Register::R13D => Register::R13,
        Register::R14D => Register::R14,
        Register::R15D => Register::R15,
        other => other,
    }
}

fn to_constraint_reg(reg: Register) -> Option<ConstraintReg> {
    match reg {
        Register::RAX | Register::EAX => Some(ConstraintReg::Rax),
        Register::RBX | Register::EBX => Some(ConstraintReg::Rbx),
        Register::RCX | Register::ECX => Some(ConstraintReg::Rcx),
        Register::RDX | Register::EDX => Some(ConstraintReg::Rdx),
        Register::RSI | Register::ESI => Some(ConstraintReg::Rsi),
        Register::RDI | Register::EDI => Some(ConstraintReg::Rdi),
        Register::R12 | Register::R12D => Some(ConstraintReg::R12),
        Register::R15 | Register::R15D => Some(ConstraintReg::R15),
        _ => None,
    }
}

/// Format a code region as disassembly text.
fn format_region(data: &[u8], base_va: u64) -> String {
    let mut decoder = Decoder::with_ip(64, data, base_va, DecoderOptions::NONE);
    let mut formatter = iced_x86::IntelFormatter::new();
    let mut output = String::new();
    let mut fmt_output = FmtOutput(String::new());

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        fmt_output.0.clear();
        formatter.format(&insn, &mut fmt_output);
        output.push_str(&format!("  {:#x}: {}\n", insn.ip(), fmt_output.0));
    }
    output
}

struct FmtOutput(String);

impl iced_x86::FormatterOutput for FmtOutput {
    fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
        self.0.push_str(text);
    }
}

/// Format one-gadget results for display.
pub fn format_one_gadgets(gadgets: &[OneGadget]) -> String {
    let mut out = String::new();
    for (i, g) in gadgets.iter().enumerate() {
        out.push_str(&format!("=== One-Gadget #{} (offset {:#x}, {}) ===\n", i + 1, g.offset, g.difficulty));
        if g.constraints.is_empty() {
            out.push_str("  Constraints: none\n");
        } else {
            out.push_str("  Constraints:\n");
            for c in &g.constraints {
                out.push_str(&format!("    {}\n", c));
            }
        }
        out.push_str(&g.disassembly);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_binsh_in_data() {
        let mut data = vec![0u8; 100];
        data[20..28].copy_from_slice(b"/bin/sh\0");
        data[50..58].copy_from_slice(b"/bin/sh\0");
        let offsets = find_binsh_strings(&data);
        assert_eq!(offsets, vec![20, 50]);
    }

    #[test]
    fn find_binsh_not_present() {
        let data = vec![0u8; 100];
        assert!(find_binsh_strings(&data).is_empty());
    }

    #[test]
    fn constraint_display() {
        assert_eq!(format!("{}", Constraint::RegNull(ConstraintReg::Rdx)), "rdx == NULL");
        assert_eq!(format!("{}", Constraint::StackNull(0x30)), "[rsp+0x30] == NULL");
        assert_eq!(format!("{}", Constraint::RspAligned), "rsp & 0xf == 0");
    }

    #[test]
    fn difficulty_ordering() {
        assert!(Difficulty::Easy < Difficulty::Medium);
        assert!(Difficulty::Medium < Difficulty::Hard);
    }

    #[test]
    fn format_empty_gadgets() {
        let out = format_one_gadgets(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn format_one_gadget() {
        let gadgets = vec![OneGadget {
            offset: 0x4f3d5,
            constraints: vec![
                Constraint::RegNull(ConstraintReg::Rcx),
                Constraint::StackNull(0x30),
            ],
            difficulty: Difficulty::Medium,
            disassembly: "  0x4f3d5: lea rdi, [rip+0x1234]\n".into(),
        }];
        let out = format_one_gadgets(&gadgets);
        assert!(out.contains("0x4f3d5"));
        assert!(out.contains("rcx == NULL"));
        assert!(out.contains("[rsp+0x30] == NULL"));
        assert!(out.contains("medium"));
    }

    #[test]
    fn xor_zeroes_register() {
        let mut regs = std::collections::HashMap::new();
        // xor eax, eax  (31 C0)
        let bytes = [0x31, 0xC0];
        let mut decoder = Decoder::with_ip(64, &bytes, 0, DecoderOptions::NONE);
        let insn = decoder.decode();
        update_reg_state(&insn, &mut regs, &[], &[]);
        assert_eq!(regs.get(&Register::RAX), Some(&SymValue::Constant(0)));
    }

    #[test]
    fn symbolic_constant_tracking() {
        let mut regs = std::collections::HashMap::new();
        // mov eax, 59  (B8 3B 00 00 00)
        let bytes = [0xB8, 0x3B, 0x00, 0x00, 0x00];
        let mut decoder = Decoder::with_ip(64, &bytes, 0, DecoderOptions::NONE);
        let insn = decoder.decode();
        update_reg_state(&insn, &mut regs, &[], &[]);
        assert_eq!(regs.get(&Register::RAX), Some(&SymValue::Constant(59)));
    }

    #[test]
    fn find_one_gadgets_empty_data() {
        assert!(find_one_gadgets(&[]).is_err());
    }
}
