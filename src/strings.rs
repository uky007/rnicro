//! String extraction from ELF binaries.
//!
//! Searches loadable ELF sections for sequences of printable
//! ASCII characters. Useful for static analysis and reconnaissance.

use std::path::Path;

use crate::error::{Error, Result};

/// An extracted string with its location in the binary.
#[derive(Debug, Clone)]
pub struct ExtractedString {
    /// Virtual address (or file offset for non-loadable sections).
    pub addr: u64,
    /// Section name where the string was found.
    pub section: String,
    /// The string content.
    pub content: String,
}

/// Extract printable ASCII strings from an ELF binary.
///
/// Scans all allocatable sections for runs of printable ASCII characters
/// of at least `min_length` bytes, terminated by a NUL byte or
/// non-printable character.
pub fn extract_strings(path: &Path, min_length: usize) -> Result<Vec<ExtractedString>> {
    let data =
        std::fs::read(path).map_err(|e| Error::Other(format!("read: {}", e)))?;
    extract_strings_bytes(&data, min_length)
}

/// Extract printable ASCII strings from raw ELF data.
pub fn extract_strings_bytes(data: &[u8], min_length: usize) -> Result<Vec<ExtractedString>> {
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    let min_length = if min_length == 0 { 4 } else { min_length };
    let mut strings = Vec::new();

    for sh in &elf.section_headers {
        // Only scan sections that are allocated in memory (SHF_ALLOC)
        if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) == 0 {
            continue;
        }

        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if offset + size > data.len() {
            continue;
        }

        let section_data = &data[offset..offset + size];
        let section_name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("<unknown>");

        let mut run_start: Option<usize> = None;

        for (i, &byte) in section_data.iter().enumerate() {
            if is_printable_ascii(byte) {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else {
                if let Some(start) = run_start {
                    let len = i - start;
                    if len >= min_length {
                        let content =
                            String::from_utf8_lossy(&section_data[start..i]).into_owned();
                        strings.push(ExtractedString {
                            addr: sh.sh_addr + start as u64,
                            section: section_name.to_string(),
                            content,
                        });
                    }
                }
                run_start = None;
            }
        }

        // Handle string at end of section
        if let Some(start) = run_start {
            let len = section_data.len() - start;
            if len >= min_length {
                let content =
                    String::from_utf8_lossy(&section_data[start..]).into_owned();
                strings.push(ExtractedString {
                    addr: sh.sh_addr + start as u64,
                    section: section_name.to_string(),
                    content,
                });
            }
        }
    }

    Ok(strings)
}

/// Check if a byte is a printable ASCII character (space through tilde, plus tab and newline).
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\n')
}

/// Extract strings from raw memory bytes (no ELF structure needed).
/// Useful for scanning process memory regions.
pub fn extract_strings_raw(
    data: &[u8],
    base_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let min_length = if min_length == 0 { 4 } else { min_length };
    let mut strings = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else {
            if let Some(start) = run_start {
                let len = i - start;
                if len >= min_length {
                    let content =
                        String::from_utf8_lossy(&data[start..i]).into_owned();
                    strings.push(ExtractedString {
                        addr: base_addr + start as u64,
                        section: String::new(),
                        content,
                    });
                }
            }
            run_start = None;
        }
    }

    if let Some(start) = run_start {
        let len = data.len() - start;
        if len >= min_length {
            let content =
                String::from_utf8_lossy(&data[start..]).into_owned();
            strings.push(ExtractedString {
                addr: base_addr + start as u64,
                section: String::new(),
                content,
            });
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'~'));
        assert!(is_printable_ascii(b'\t'));
        assert!(is_printable_ascii(b'\n'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x01));
        assert!(!is_printable_ascii(0x80));
        assert!(!is_printable_ascii(0xff));
    }

    #[test]
    fn extract_strings_from_raw() {
        let data = b"\x00Hello, World!\x00\x01\x02abc\x00This is a longer string\x00";
        let result = extract_strings_raw(data, 0x1000, 4);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].content, "Hello, World!");
        assert_eq!(result[0].addr, 0x1001);
        assert_eq!(result[1].content, "This is a longer string");
    }

    #[test]
    fn min_length_filtering() {
        let data = b"\x00ab\x00abcd\x00abcdefgh\x00";
        let result = extract_strings_raw(data, 0, 4);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].content, "abcd");
        assert_eq!(result[1].content, "abcdefgh");
    }

    #[test]
    fn empty_input() {
        let result = extract_strings_raw(b"", 0, 4);
        assert!(result.is_empty());
    }
}
