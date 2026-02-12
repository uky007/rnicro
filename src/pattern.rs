//! De Bruijn cyclic pattern generation for buffer overflow analysis.
//!
//! Generates unique cyclic patterns where every N-character subsequence
//! appears exactly once. Used to determine exact buffer overflow offsets
//! by finding where a pattern appears in a register or memory.

use crate::error::{Error, Result};

/// Character sets used for pattern generation.
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";

/// Generate a De Bruijn cyclic pattern of the given length.
///
/// The pattern uses 3 character sets (uppercase, lowercase, digits)
/// with a subsequence length of 3, giving unique 3-byte subsequences.
/// Maximum pattern length is 26 * 26 * 10 = 6760 bytes.
pub fn create(length: usize) -> Result<String> {
    let max_len = UPPER.len() * LOWER.len() * DIGITS.len();
    if length > max_len {
        return Err(Error::Other(format!(
            "pattern length {} exceeds maximum {} (26*26*10)",
            length, max_len
        )));
    }

    let mut pattern = String::with_capacity(length);

    'outer: for &u in UPPER {
        for &l in LOWER {
            for &d in DIGITS {
                if pattern.len() >= length {
                    break 'outer;
                }
                pattern.push(u as char);
                if pattern.len() >= length {
                    break 'outer;
                }
                pattern.push(l as char);
                if pattern.len() >= length {
                    break 'outer;
                }
                pattern.push(d as char);
            }
        }
    }

    Ok(pattern)
}

/// Find the offset of a 4-byte value within the cyclic pattern.
///
/// The value can be provided as a u32 (e.g., from a register dump)
/// and the function searches both little-endian and big-endian
/// representations in the pattern.
pub fn offset_of(value: u32) -> Result<Option<usize>> {
    let le_bytes = value.to_le_bytes();
    let be_bytes = value.to_be_bytes();

    // Generate the maximum pattern
    let max_len = UPPER.len() * LOWER.len() * DIGITS.len();
    let pattern = create(max_len)?;
    let pattern_bytes = pattern.as_bytes();

    // Search for little-endian first (most common on x86)
    if let Some(pos) = find_subsequence(pattern_bytes, &le_bytes) {
        return Ok(Some(pos));
    }

    // Try big-endian
    if let Some(pos) = find_subsequence(pattern_bytes, &be_bytes) {
        return Ok(Some(pos));
    }

    Ok(None)
}

/// Find the offset of a byte string within the cyclic pattern.
pub fn offset_of_bytes(needle: &[u8]) -> Result<Option<usize>> {
    let max_len = UPPER.len() * LOWER.len() * DIGITS.len();
    let pattern = create(max_len)?;
    let pattern_bytes = pattern.as_bytes();

    Ok(find_subsequence(pattern_bytes, needle))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_starts_correctly() {
        let pattern = create(12).unwrap();
        assert_eq!(&pattern[..12], "Aa0Aa1Aa2Aa3");
    }

    #[test]
    fn pattern_length() {
        let pattern = create(100).unwrap();
        assert_eq!(pattern.len(), 100);
    }

    #[test]
    fn pattern_max_length() {
        let max = 26 * 26 * 10;
        let pattern = create(max).unwrap();
        assert_eq!(pattern.len(), max);
    }

    #[test]
    fn pattern_exceeds_max() {
        let max = 26 * 26 * 10;
        assert!(create(max + 1).is_err());
    }

    #[test]
    fn offset_found() {
        let pattern = create(200).unwrap();
        // Take 4 bytes at offset 50
        let bytes = &pattern.as_bytes()[50..54];
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        let found = offset_of(val).unwrap();
        assert_eq!(found, Some(50));
    }

    #[test]
    fn offset_at_zero() {
        let pattern = create(100).unwrap();
        let bytes = &pattern.as_bytes()[0..4];
        let val = u32::from_le_bytes(bytes.try_into().unwrap());
        let found = offset_of(val).unwrap();
        assert_eq!(found, Some(0));
    }

    #[test]
    fn offset_not_found() {
        let found = offset_of(0xDEADBEEF).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn unique_subsequences() {
        let pattern = create(300).unwrap();
        let bytes = pattern.as_bytes();
        // Check that every 4-byte window at 3-byte stride is unique
        let mut seen = std::collections::HashSet::new();
        for chunk in bytes.windows(3) {
            assert!(
                seen.insert(chunk.to_vec()),
                "duplicate 3-byte subsequence found: {:?}",
                chunk
            );
        }
    }

    #[test]
    fn offset_of_bytes_works() {
        let pattern = create(200).unwrap();
        let needle = &pattern.as_bytes()[30..34];
        let found = offset_of_bytes(needle).unwrap();
        assert_eq!(found, Some(30));
    }
}
