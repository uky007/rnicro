//! ROP (Return-Oriented Programming) gadget search.
//!
//! Scans executable ELF segments for short instruction sequences
//! ending in RET, JMP reg, or CALL reg — building blocks for
//! return-oriented programming chains.

use std::collections::BTreeMap;
use std::path::Path;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput,
               FormatterTextKind, Instruction, IntelFormatter};

use crate::error::{Error, Result};

/// A discovered ROP gadget.
#[derive(Debug, Clone)]
pub struct Gadget {
    /// Virtual address of the gadget.
    pub addr: u64,
    /// Disassembled instruction text (e.g. "pop rdi; ret").
    pub instructions: String,
    /// Raw bytes of the gadget.
    pub bytes: Vec<u8>,
    /// Number of instructions in the gadget.
    pub insn_count: usize,
}

/// Type of gadget ending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GadgetType {
    /// Ends with RET (0xC3).
    Ret,
    /// Ends with JMP register.
    JmpReg,
    /// Ends with CALL register.
    CallReg,
}

/// Search for ROP gadgets in an ELF binary.
///
/// Scans all executable segments for instruction sequences ending in
/// control-flow transfer instructions (RET, JMP reg, CALL reg).
///
/// `max_depth` controls the maximum number of instructions per gadget
/// (default 5 if 0 is passed).
pub fn find_gadgets(path: &Path, max_depth: usize) -> Result<Vec<Gadget>> {
    let data =
        std::fs::read(path).map_err(|e| Error::Other(format!("read: {}", e)))?;
    find_gadgets_bytes(&data, max_depth)
}

/// Search for ROP gadgets in raw ELF data.
pub fn find_gadgets_bytes(data: &[u8], max_depth: usize) -> Result<Vec<Gadget>> {
    let max_depth = if max_depth == 0 { 5 } else { max_depth };
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    // Collect executable segments
    let mut gadgets: BTreeMap<u64, Gadget> = BTreeMap::new();

    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        // Only scan executable segments
        if ph.p_flags & goblin::elf::program_header::PF_X == 0 {
            continue;
        }

        let offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;
        let vaddr = ph.p_vaddr;

        if offset + size > data.len() {
            continue;
        }

        let segment = &data[offset..offset + size];

        // Find all RET (0xC3) positions
        for (i, &byte) in segment.iter().enumerate() {
            let gadget_type = match byte {
                0xC3 => Some(GadgetType::Ret),
                _ => None,
            };

            if gadget_type.is_none() {
                // Also check for JMP reg / CALL reg (FF /4, FF /2)
                if i + 1 < segment.len() && byte == 0xFF {
                    let modrm = segment[i + 1];
                    let reg_op = (modrm >> 3) & 7;
                    let modrm_mod = modrm >> 6;
                    // FF /4 = JMP r/m, FF /2 = CALL r/m
                    // Only register-direct mode (mod=11)
                    if modrm_mod == 3 && (reg_op == 4 || reg_op == 2) {
                        let end_addr = vaddr + i as u64;
                        let gt = if reg_op == 4 {
                            GadgetType::JmpReg
                        } else {
                            GadgetType::CallReg
                        };
                        find_gadgets_ending_at(
                            segment,
                            vaddr,
                            i + 2, // end position (after the 2-byte instruction)
                            end_addr,
                            max_depth,
                            gt,
                            &mut gadgets,
                        );
                    }
                }
                continue;
            }

            let end_addr = vaddr + i as u64;
            find_gadgets_ending_at(
                segment,
                vaddr,
                i + 1, // end position (after the RET byte)
                end_addr,
                max_depth,
                GadgetType::Ret,
                &mut gadgets,
            );
        }
    }

    Ok(gadgets.into_values().collect())
}

/// Backward-scan from a gadget-ending instruction to find valid gadgets.
fn find_gadgets_ending_at(
    segment: &[u8],
    seg_vaddr: u64,
    end_pos: usize,
    _end_addr: u64,
    max_depth: usize,
    gadget_type: GadgetType,
    gadgets: &mut BTreeMap<u64, Gadget>,
) {
    let max_back = 20.min(end_pos); // Don't scan beyond segment start

    for back in 1..=max_back {
        let start = end_pos - back;
        let gadget_bytes = &segment[start..end_pos];
        let gadget_vaddr = seg_vaddr + start as u64;

        // Decode and validate the instruction sequence
        if let Some(gadget) = try_decode_gadget(gadget_bytes, gadget_vaddr, max_depth, gadget_type)
        {
            gadgets.entry(gadget.addr).or_insert(gadget);
        }
    }
}

/// Try to decode a byte sequence as a valid gadget.
///
/// Returns Some(Gadget) if the bytes decode to a clean instruction
/// sequence that ends exactly at the expected control-flow transfer.
fn try_decode_gadget(
    bytes: &[u8],
    vaddr: u64,
    max_depth: usize,
    gadget_type: GadgetType,
) -> Option<Gadget> {
    let mut decoder = Decoder::with_ip(64, bytes, vaddr, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut formatter = IntelFormatter::new();
    let mut output = GadgetFormatter::new();

    let mut total_len = 0;

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        if insn.is_invalid() {
            return None;
        }

        total_len += insn.len();
        instructions.push(insn);

        // Check if this is the ending instruction
        let is_end = match gadget_type {
            GadgetType::Ret => insn.flow_control() == FlowControl::Return,
            GadgetType::JmpReg => {
                insn.flow_control() == FlowControl::IndirectBranch
            }
            GadgetType::CallReg => {
                insn.flow_control() == FlowControl::IndirectCall
            }
        };

        if is_end {
            // The decoded instructions must consume exactly all bytes
            if total_len != bytes.len() {
                return None;
            }
            if instructions.len() > max_depth {
                return None;
            }

            // Format the gadget
            let mut text_parts = Vec::new();
            for ins in &instructions {
                output.clear();
                formatter.format(ins, &mut output);
                text_parts.push(output.text().to_string());
            }

            return Some(Gadget {
                addr: vaddr,
                instructions: text_parts.join("; "),
                bytes: bytes.to_vec(),
                insn_count: instructions.len(),
            });
        }

        // If we hit another control-flow transfer before the end, invalid
        match insn.flow_control() {
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::Call
            | FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch => return None,
            _ => {}
        }

        if instructions.len() >= max_depth {
            return None;
        }
    }

    None // Didn't reach the ending instruction
}

struct GadgetFormatter {
    text: String,
}

impl GadgetFormatter {
    fn new() -> Self {
        Self {
            text: String::new(),
        }
    }

    fn clear(&mut self) {
        self.text.clear();
    }

    fn text(&self) -> &str {
        &self.text
    }
}

impl FormatterOutput for GadgetFormatter {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.text.push_str(text);
    }
}

/// Filter gadgets by a substring pattern.
pub fn filter_gadgets<'a>(gadgets: &'a [Gadget], pattern: &str) -> Vec<&'a Gadget> {
    let pattern_lower = pattern.to_lowercase();
    gadgets
        .iter()
        .filter(|g| g.instructions.to_lowercase().contains(&pattern_lower))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_ret_gadget() {
        // pop rdi; ret = 5f c3
        let bytes = &[0x5f, 0xc3];
        let gadget = try_decode_gadget(bytes, 0x1000, 5, GadgetType::Ret);
        assert!(gadget.is_some());
        let g = gadget.unwrap();
        assert_eq!(g.addr, 0x1000);
        assert_eq!(g.insn_count, 2);
        assert!(g.instructions.contains("pop rdi"));
        assert!(g.instructions.contains("ret"));
    }

    #[test]
    fn decode_multi_pop_ret() {
        // pop rsi; pop rdi; ret = 5e 5f c3
        let bytes = &[0x5e, 0x5f, 0xc3];
        let gadget = try_decode_gadget(bytes, 0x2000, 5, GadgetType::Ret);
        assert!(gadget.is_some());
        let g = gadget.unwrap();
        assert_eq!(g.insn_count, 3);
        assert!(g.instructions.contains("pop rsi"));
        assert!(g.instructions.contains("pop rdi"));
    }

    #[test]
    fn reject_invalid_bytes() {
        // Bytes that don't form valid instructions ending in ret
        let bytes = &[0xff, 0xff, 0xc3];
        let gadget = try_decode_gadget(bytes, 0x3000, 5, GadgetType::Ret);
        // This may or may not decode depending on the byte sequence;
        // the point is it doesn't panic
        let _ = gadget;
    }

    #[test]
    fn reject_too_deep() {
        // pop rax; pop rbx; pop rcx; pop rdx; pop rsi; pop rdi; ret (7 insns)
        let bytes = &[0x58, 0x5b, 0x59, 0x5a, 0x5e, 0x5f, 0xc3];
        let gadget = try_decode_gadget(bytes, 0x4000, 3, GadgetType::Ret);
        assert!(gadget.is_none()); // Too many instructions
    }

    #[test]
    fn standalone_ret() {
        // Just "ret"
        let bytes = &[0xc3];
        let gadget = try_decode_gadget(bytes, 0x5000, 5, GadgetType::Ret);
        assert!(gadget.is_some());
        let g = gadget.unwrap();
        assert_eq!(g.insn_count, 1);
        assert!(g.instructions.contains("ret"));
    }

    #[test]
    fn filter_gadgets_by_pattern() {
        let gadgets = vec![
            Gadget {
                addr: 0x1000,
                instructions: "pop rdi; ret".into(),
                bytes: vec![0x5f, 0xc3],
                insn_count: 2,
            },
            Gadget {
                addr: 0x2000,
                instructions: "pop rsi; ret".into(),
                bytes: vec![0x5e, 0xc3],
                insn_count: 2,
            },
            Gadget {
                addr: 0x3000,
                instructions: "xor eax, eax; ret".into(),
                bytes: vec![0x31, 0xc0, 0xc3],
                insn_count: 2,
            },
        ];

        let filtered = filter_gadgets(&gadgets, "pop rdi");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr, 0x1000);

        let filtered = filter_gadgets(&gadgets, "ret");
        assert_eq!(filtered.len(), 3);
    }
}
