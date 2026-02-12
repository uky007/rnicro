//! Memory scanning and pattern matching.
//!
//! Provides byte pattern search with IDA-style wildcard support,
//! value scanning, and differential scanning for game hacking.

use crate::error::{Error, Result};

/// A match found during memory scanning.
#[derive(Debug, Clone)]
pub struct ScanMatch {
    /// Address where the match was found.
    pub address: u64,
    /// Matched bytes.
    pub matched_bytes: Vec<u8>,
    /// Name/description of the pattern.
    pub pattern_name: String,
}

/// Parse an IDA-style hex pattern into bytes and mask.
///
/// Pattern format: `"48 8B ?? 05 90"` where `??` is a wildcard byte.
/// Returns `(bytes, mask)` where `mask[i] == true` means `bytes[i]` must match.
pub fn parse_hex_pattern(pattern: &str) -> Result<(Vec<u8>, Vec<bool>)> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();

    for token in pattern.split_whitespace() {
        if token == "??" || token == "?" {
            bytes.push(0);
            mask.push(false);
        } else {
            let b = u8::from_str_radix(token, 16)
                .map_err(|_| Error::Other(format!("invalid hex byte: '{}'", token)))?;
            bytes.push(b);
            mask.push(true);
        }
    }

    if bytes.is_empty() {
        return Err(Error::Other("empty pattern".into()));
    }

    Ok((bytes, mask))
}

/// Scan a buffer for a byte pattern with optional wildcards.
///
/// Returns offsets within the buffer where matches start.
pub fn scan_pattern(data: &[u8], pattern: &[u8], mask: &[bool]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    'outer: for i in 0..=data.len() - pattern.len() {
        for (j, (&pat_byte, &must_match)) in pattern.iter().zip(mask.iter()).enumerate() {
            if must_match && data[i + j] != pat_byte {
                continue 'outer;
            }
        }
        matches.push(i);
    }
    matches
}

/// Scan a buffer for an exact byte sequence.
pub fn scan_bytes(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return Vec::new();
    }
    let mask = vec![true; needle.len()];
    scan_pattern(data, needle, &mask)
}

/// Scan for a u32 value (little-endian).
pub fn scan_u32(data: &[u8], value: u32) -> Vec<usize> {
    scan_bytes(data, &value.to_le_bytes())
}

/// Scan for a u64 value (little-endian).
pub fn scan_u64(data: &[u8], value: u64) -> Vec<usize> {
    scan_bytes(data, &value.to_le_bytes())
}

/// Scan for an i32 value (little-endian).
pub fn scan_i32(data: &[u8], value: i32) -> Vec<usize> {
    scan_bytes(data, &value.to_le_bytes())
}

/// Scan for an f32 value (little-endian).
pub fn scan_f32(data: &[u8], value: f32) -> Vec<usize> {
    scan_bytes(data, &value.to_le_bytes())
}

/// Scan for a UTF-8 string (no null terminator).
pub fn scan_string(data: &[u8], needle: &str) -> Vec<usize> {
    scan_bytes(data, needle.as_bytes())
}

/// Differential scan: from previous match offsets, keep only those
/// where the buffer now contains `new_value`.
pub fn diff_scan(data: &[u8], previous_offsets: &[usize], new_value: &[u8]) -> Vec<usize> {
    previous_offsets
        .iter()
        .copied()
        .filter(|&off| {
            off + new_value.len() <= data.len()
                && &data[off..off + new_value.len()] == new_value
        })
        .collect()
}

/// Scan process memory across multiple regions.
///
/// `read_mem` reads bytes from the target process at a given (address, length).
/// Returns matches with absolute addresses.
pub fn scan_regions<F>(
    regions: &[(u64, u64)],
    pattern: &[u8],
    mask: &[bool],
    read_mem: &F,
) -> Result<Vec<ScanMatch>>
where
    F: Fn(u64, usize) -> Result<Vec<u8>>,
{
    let mut all_matches = Vec::new();

    for &(start, end) in regions {
        let size = (end - start) as usize;
        if size == 0 || size > 256 * 1024 * 1024 {
            continue; // skip empty or very large regions
        }
        let data = match read_mem(start, size) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let offsets = scan_pattern(&data, pattern, mask);
        for off in offsets {
            let addr = start + off as u64;
            let end_off = (off + pattern.len()).min(data.len());
            all_matches.push(ScanMatch {
                address: addr,
                matched_bytes: data[off..end_off].to_vec(),
                pattern_name: String::new(),
            });
        }
    }

    Ok(all_matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pattern_basic() {
        let (bytes, mask) = parse_hex_pattern("48 8B ?? 05").unwrap();
        assert_eq!(bytes, vec![0x48, 0x8B, 0x00, 0x05]);
        assert_eq!(mask, vec![true, true, false, true]);
    }

    #[test]
    fn parse_pattern_all_wildcards() {
        let (_, mask) = parse_hex_pattern("?? ?? ??").unwrap();
        assert!(mask.iter().all(|&m| !m));
    }

    #[test]
    fn parse_pattern_empty() {
        assert!(parse_hex_pattern("").is_err());
    }

    #[test]
    fn parse_pattern_invalid_hex() {
        assert!(parse_hex_pattern("ZZ").is_err());
    }

    #[test]
    fn scan_exact_match() {
        let data = b"\x48\x8B\x05\x00\x00\x48\x8B\x05";
        let matches = scan_bytes(data, &[0x48, 0x8B, 0x05]);
        assert_eq!(matches, vec![0, 5]);
    }

    #[test]
    fn scan_with_wildcards() {
        let data = b"\x48\x8B\xFF\x05\x48\x8B\x00\x05";
        let (pattern, mask) = parse_hex_pattern("48 8B ?? 05").unwrap();
        let matches = scan_pattern(data, &pattern, &mask);
        assert_eq!(matches, vec![0, 4]);
    }

    #[test]
    fn scan_no_match() {
        let data = b"\x00\x00\x00\x00";
        let matches = scan_bytes(data, &[0xFF, 0xFF]);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_u32_value() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&42u32.to_le_bytes());
        data[12..16].copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(scan_u32(&data, 42), vec![4, 12]);
    }

    #[test]
    fn scan_string_value() {
        let data = b"hello world hello rust";
        let matches = scan_string(data, "hello");
        assert_eq!(matches, vec![0, 12]);
    }

    #[test]
    fn diff_scan_filters() {
        let data1 = vec![0x41, 0x42, 0x43, 0x41, 0x44];
        let prev = scan_bytes(&data1, &[0x41]);
        assert_eq!(prev, vec![0, 3]);

        let data2 = vec![0x41, 0x42, 0x43, 0x99, 0x44];
        let result = diff_scan(&data2, &prev, &[0x41]);
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn scan_regions_basic() {
        let read_mem = |addr: u64, len: usize| -> Result<Vec<u8>> {
            let mut data = vec![0u8; len];
            if addr == 0x1000 && len >= 8 {
                data[4..8].copy_from_slice(&[0x48, 0x89, 0xE5, 0xCC]);
            }
            Ok(data)
        };
        let regions = vec![(0x1000u64, 0x1100u64)];
        let (pattern, mask) = parse_hex_pattern("48 89 E5").unwrap();
        let matches = scan_regions(&regions, &pattern, &mask, &read_mem).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x1004);
    }

    #[test]
    fn scan_f32_value() {
        let mut data = vec![0u8; 12];
        data[4..8].copy_from_slice(&3.14f32.to_le_bytes());
        assert_eq!(scan_f32(&data, 3.14), vec![4]);
    }
}
