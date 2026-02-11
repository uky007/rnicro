//! x86_64 disassembly using iced-x86.
//!
//! Corresponds to book Ch.8 (Memory and Disassembly).
//! Provides instruction decoding and formatted output for
//! examining code in the tracee's memory.

use iced_x86::{Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind,
               GasFormatter, IntelFormatter, Instruction};

use crate::types::VirtAddr;

/// Disassembly output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmStyle {
    /// Intel syntax (e.g., `mov rax, [rbx+8]`)
    Intel,
    /// AT&T / GAS syntax (e.g., `movq 8(%rbx), %rax`)
    Gas,
}

/// A single disassembled instruction.
#[derive(Debug, Clone)]
pub struct DisasmInstruction {
    /// Address of the instruction.
    pub addr: VirtAddr,
    /// Raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// Formatted mnemonic + operands.
    pub text: String,
    /// Length of the instruction in bytes.
    pub len: usize,
}

/// Disassemble a block of code bytes.
///
/// # Arguments
/// * `code` - Raw bytes to disassemble.
/// * `base_addr` - Virtual address of the first byte.
/// * `count` - Maximum number of instructions to decode.
/// * `style` - Output format (Intel or AT&T).
pub fn disassemble(
    code: &[u8],
    base_addr: VirtAddr,
    count: usize,
    style: DisasmStyle,
) -> Vec<DisasmInstruction> {
    let mut decoder = Decoder::with_ip(64, code, base_addr.addr(), DecoderOptions::NONE);
    let mut results = Vec::new();
    let mut output = FormatterOutputBuffer::new();

    while decoder.can_decode() && results.len() < count {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        output.clear();
        match style {
            DisasmStyle::Intel => {
                let mut formatter = IntelFormatter::new();
                formatter.format(&insn, &mut output);
            }
            DisasmStyle::Gas => {
                let mut formatter = GasFormatter::new();
                formatter.format(&insn, &mut output);
            }
        }

        let insn_bytes = &code[(insn.ip() - base_addr.addr()) as usize..
                               (insn.ip() - base_addr.addr()) as usize + insn.len()];

        results.push(DisasmInstruction {
            addr: VirtAddr(insn.ip()),
            bytes: insn_bytes.to_vec(),
            text: output.text().to_string(),
            len: insn.len(),
        });
    }

    results
}

/// Format disassembly output as a human-readable string.
pub fn format_disassembly(instructions: &[DisasmInstruction]) -> String {
    let mut out = String::new();
    for insn in instructions {
        // Address
        out.push_str(&format!("  {:016x}  ", insn.addr.addr()));

        // Raw bytes (padded to 10 bytes width)
        let mut bytes_str = String::new();
        for b in &insn.bytes {
            bytes_str.push_str(&format!("{:02x} ", b));
        }
        out.push_str(&format!("{:<30} ", bytes_str.trim_end()));

        // Mnemonic
        out.push_str(&insn.text);
        out.push('\n');
    }
    out
}

/// Internal buffer for iced-x86 formatter output.
struct FormatterOutputBuffer {
    text: String,
}

impl FormatterOutputBuffer {
    fn new() -> Self {
        Self { text: String::new() }
    }

    fn clear(&mut self) {
        self.text.clear();
    }

    fn text(&self) -> &str {
        &self.text
    }
}

impl FormatterOutput for FormatterOutputBuffer {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.text.push_str(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disassemble_nops() {
        // 3 NOP instructions (0x90)
        let code = [0x90, 0x90, 0x90];
        let insns = disassemble(&code, VirtAddr(0x1000), 10, DisasmStyle::Intel);
        assert_eq!(insns.len(), 3);
        for insn in &insns {
            assert_eq!(insn.text, "nop");
            assert_eq!(insn.len, 1);
            assert_eq!(insn.bytes, vec![0x90]);
        }
        assert_eq!(insns[0].addr, VirtAddr(0x1000));
        assert_eq!(insns[1].addr, VirtAddr(0x1001));
        assert_eq!(insns[2].addr, VirtAddr(0x1002));
    }

    #[test]
    fn disassemble_push_rbp_sequence() {
        // push rbp; mov rbp, rsp; sub rsp, 0x10
        let code = [
            0x55,                         // push rbp
            0x48, 0x89, 0xe5,             // mov rbp, rsp
            0x48, 0x83, 0xec, 0x10,       // sub rsp, 0x10
        ];
        let insns = disassemble(&code, VirtAddr(0x401000), 10, DisasmStyle::Intel);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].text, "push rbp");
        assert_eq!(insns[0].len, 1);
        assert!(insns[1].text.contains("mov"));
        assert!(insns[1].text.contains("rbp"));
        assert_eq!(insns[1].len, 3);
        assert!(insns[2].text.contains("sub"));
        assert_eq!(insns[2].len, 4);
    }

    #[test]
    fn disassemble_count_limit() {
        let code = [0x90; 100]; // 100 NOPs
        let insns = disassemble(&code, VirtAddr(0x0), 5, DisasmStyle::Intel);
        assert_eq!(insns.len(), 5);
    }

    #[test]
    fn disassemble_gas_style() {
        let code = [0x55]; // push rbp
        let insns = disassemble(&code, VirtAddr(0x0), 1, DisasmStyle::Gas);
        assert_eq!(insns.len(), 1);
        // GAS uses %rbp
        assert!(insns[0].text.contains("%rbp"));
    }

    #[test]
    fn format_disassembly_output() {
        let code = [0x90, 0xcc]; // nop; int3
        let insns = disassemble(&code, VirtAddr(0x1000), 10, DisasmStyle::Intel);
        let output = format_disassembly(&insns);
        assert!(output.contains("0000000000001000"));
        assert!(output.contains("nop"));
        assert!(output.contains("int3"));
    }
}
