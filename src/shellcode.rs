//! Shellcode analysis and transformation toolkit.
//!
//! Provides encoding, decoding, bad character detection,
//! NOP sled detection, and shellcode extraction from ELF binaries.

use crate::error::{Error, Result};

/// Analysis results for a shellcode buffer.
#[derive(Debug, Clone)]
pub struct ShellcodeAnalysis {
    /// Total size in bytes.
    pub size: usize,
    /// Whether the shellcode contains null bytes.
    pub has_null_bytes: bool,
    /// Positions of null bytes.
    pub null_positions: Vec<usize>,
    /// Positions and values of bad characters.
    pub bad_chars: Vec<(usize, u8)>,
    /// Detected NOP sleds.
    pub nop_sleds: Vec<NopSled>,
    /// Positions of `syscall` instructions (0x0F 0x05).
    pub syscall_sites: Vec<usize>,
    /// Positions of `int 0x80` instructions (0xCD 0x80).
    pub int80_sites: Vec<usize>,
}

/// A detected NOP sled.
#[derive(Debug, Clone)]
pub struct NopSled {
    /// Byte offset of the sled start.
    pub offset: usize,
    /// Length in bytes.
    pub length: usize,
    /// Type of NOP used.
    pub sled_type: NopType,
}

/// NOP instruction classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NopType {
    /// Classic single-byte NOP (0x90).
    Classic,
}

impl std::fmt::Display for NopType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Classic => write!(f, "NOP (0x90)"),
        }
    }
}

/// Analyze shellcode for common properties.
///
/// Detects null bytes, bad characters, NOP sleds, and syscall sites.
pub fn analyze(shellcode: &[u8], bad_chars: &[u8]) -> ShellcodeAnalysis {
    let null_positions: Vec<usize> = shellcode
        .iter()
        .enumerate()
        .filter(|(_, &b)| b == 0)
        .map(|(i, _)| i)
        .collect();

    let bad_char_positions: Vec<(usize, u8)> = shellcode
        .iter()
        .enumerate()
        .filter(|(_, b)| bad_chars.contains(b))
        .map(|(i, &b)| (i, b))
        .collect();

    let nop_sleds = detect_nop_sleds(shellcode);
    let syscall_sites = find_opcodes(shellcode, &[0x0F, 0x05]);
    let int80_sites = find_opcodes(shellcode, &[0xCD, 0x80]);

    ShellcodeAnalysis {
        size: shellcode.len(),
        has_null_bytes: !null_positions.is_empty(),
        null_positions,
        bad_chars: bad_char_positions,
        nop_sleds,
        syscall_sites,
        int80_sites,
    }
}

/// Find all positions of a multi-byte opcode sequence.
fn find_opcodes(data: &[u8], opcode: &[u8]) -> Vec<usize> {
    if opcode.is_empty() || data.len() < opcode.len() {
        return Vec::new();
    }
    data.windows(opcode.len())
        .enumerate()
        .filter(|(_, w)| *w == opcode)
        .map(|(i, _)| i)
        .collect()
}

/// Detect NOP sleds (runs of 4+ consecutive 0x90 bytes).
pub fn detect_nop_sleds(data: &[u8]) -> Vec<NopSled> {
    let min_sled_len = 4;
    let mut sleds = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if data[i] == 0x90 {
            let start = i;
            while i < data.len() && data[i] == 0x90 {
                i += 1;
            }
            let len = i - start;
            if len >= min_sled_len {
                sleds.push(NopSled {
                    offset: start,
                    length: len,
                    sled_type: NopType::Classic,
                });
            }
        } else {
            i += 1;
        }
    }

    sleds
}

/// XOR encode shellcode with a single-byte key.
pub fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
    shellcode.iter().map(|&b| b ^ key).collect()
}

/// XOR decode shellcode (symmetric with encode).
pub fn xor_decode(encoded: &[u8], key: u8) -> Vec<u8> {
    xor_encode(encoded, key)
}

/// Find a single-byte XOR key that avoids all bad characters in the output.
///
/// Returns `None` if no suitable key exists (all 255 keys produce at
/// least one bad character).
pub fn find_xor_key(shellcode: &[u8], bad_chars: &[u8]) -> Option<u8> {
    for key in 1u8..=255 {
        if bad_chars.contains(&key) {
            continue;
        }
        let encoded = xor_encode(shellcode, key);
        if !encoded.iter().any(|b| bad_chars.contains(b)) {
            return Some(key);
        }
    }
    None
}

/// Generate a XOR decoder stub for x86_64.
///
/// The stub decodes `encoded_len` bytes located immediately after itself.
///
/// ```text
///   lea rsi, [rip + offset]   ; point to encoded shellcode
///   xor rcx, rcx
///   mov cl, <len>             ; loop count
/// loop:
///   xor byte [rsi], <key>
///   inc rsi
///   loop loop
///   ; falls through to decoded shellcode
/// ```
pub fn xor_decoder_stub(key: u8, encoded_len: u8) -> Vec<u8> {
    let mut stub = Vec::new();

    // lea rsi, [rip + imm32]
    stub.extend_from_slice(&[0x48, 0x8D, 0x35]);
    let rip_offset_pos = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // xor rcx, rcx
    stub.extend_from_slice(&[0x48, 0x31, 0xC9]);

    // mov cl, encoded_len
    stub.extend_from_slice(&[0xB1, encoded_len]);

    // loop body start
    let loop_start = stub.len();

    // xor byte [rsi], key
    stub.extend_from_slice(&[0x80, 0x36, key]);

    // inc rsi
    stub.extend_from_slice(&[0x48, 0xFF, 0xC6]);

    // loop rel8
    let loop_end = stub.len() + 2;
    let rel_offset = (loop_start as i32 - loop_end as i32) as i8;
    stub.extend_from_slice(&[0xE2, rel_offset as u8]);

    // Fix up RIP-relative offset for lea
    let rip_after_lea = rip_offset_pos + 4;
    let shellcode_start = stub.len();
    let offset = (shellcode_start - rip_after_lea) as i32;
    stub[rip_offset_pos..rip_offset_pos + 4].copy_from_slice(&offset.to_le_bytes());

    stub
}

/// Find bad characters in shellcode.
pub fn find_bad_chars(shellcode: &[u8], bad: &[u8]) -> Vec<(usize, u8)> {
    shellcode
        .iter()
        .enumerate()
        .filter(|(_, b)| bad.contains(b))
        .map(|(i, &b)| (i, b))
        .collect()
}

/// Common bad character sets.
pub const BAD_CHARS_NULL: &[u8] = &[0x00];
pub const BAD_CHARS_BASIC: &[u8] = &[0x00, 0x0A, 0x0D];
pub const BAD_CHARS_STRICT: &[u8] = &[0x00, 0x0A, 0x0D, 0x20, 0x09, 0x0B, 0x0C, 0xFF];

/// Extract raw bytes from a named ELF section.
pub fn extract_from_section(elf_data: &[u8], section_name: &str) -> Result<Vec<u8>> {
    let elf = goblin::elf::Elf::parse(elf_data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == section_name {
            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            if offset + size <= elf_data.len() {
                return Ok(elf_data[offset..offset + size].to_vec());
            }
        }
    }
    Err(Error::Other(format!("section '{}' not found", section_name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_clean_shellcode() {
        let shellcode = b"\x48\x31\xc0\x48\x89\xc7\x0f\x05";
        let result = analyze(shellcode, BAD_CHARS_NULL);
        assert_eq!(result.size, 8);
        assert!(!result.has_null_bytes);
        assert_eq!(result.syscall_sites, vec![6]);
    }

    #[test]
    fn analyze_with_nulls() {
        let shellcode = b"\x00\x90\x00\x90";
        let result = analyze(shellcode, BAD_CHARS_NULL);
        assert!(result.has_null_bytes);
        assert_eq!(result.null_positions, vec![0, 2]);
    }

    #[test]
    fn nop_sled_detected() {
        let data = b"\xCC\x90\x90\x90\x90\x90\xCC";
        let sleds = detect_nop_sleds(data);
        assert_eq!(sleds.len(), 1);
        assert_eq!(sleds[0].offset, 1);
        assert_eq!(sleds[0].length, 5);
    }

    #[test]
    fn nop_sled_too_short() {
        let sleds = detect_nop_sleds(b"\x90\x90\x90");
        assert!(sleds.is_empty());
    }

    #[test]
    fn xor_roundtrip() {
        let original = b"\x48\x31\xc0\x0f\x05";
        let key = 0x41;
        let encoded = xor_encode(original, key);
        let decoded = xor_decode(&encoded, key);
        assert_eq!(decoded, original);
    }

    #[test]
    fn xor_changes_bytes() {
        let original = b"\x48\x31\xc0";
        let encoded = xor_encode(original, 0xFF);
        assert_eq!(encoded, vec![0x48 ^ 0xFF, 0x31 ^ 0xFF, 0xc0 ^ 0xFF]);
    }

    #[test]
    fn find_key_avoids_bad() {
        let shellcode = b"\x48\x31\xc0";
        let key = find_xor_key(shellcode, BAD_CHARS_BASIC).unwrap();
        let encoded = xor_encode(shellcode, key);
        assert!(!encoded.iter().any(|b| BAD_CHARS_BASIC.contains(b)));
    }

    #[test]
    fn bad_chars_detection() {
        let shellcode = b"\x48\x00\x31\x0a\xc0";
        let bad = find_bad_chars(shellcode, BAD_CHARS_BASIC);
        assert_eq!(bad.len(), 2);
        assert_eq!(bad[0], (1, 0x00));
        assert_eq!(bad[1], (3, 0x0A));
    }

    #[test]
    fn int80_detection() {
        let data = b"\xb0\x01\xcd\x80";
        let result = analyze(data, BAD_CHARS_NULL);
        assert_eq!(result.int80_sites, vec![2]);
    }

    #[test]
    fn syscall_detection() {
        let data = b"\x48\x31\xc0\x0f\x05\x90\x0f\x05";
        let result = analyze(data, &[]);
        assert_eq!(result.syscall_sites, vec![3, 6]);
    }

    #[test]
    fn decoder_stub_valid() {
        let stub = xor_decoder_stub(0x41, 10);
        assert!(!stub.is_empty());
        assert!(stub.contains(&0x41)); // key
        assert!(stub.contains(&10));   // length
    }
}
