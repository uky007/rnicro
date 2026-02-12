//! Shannon entropy analysis for ELF sections.
//!
//! Computes byte-level entropy to identify packed/encrypted content,
//! padding regions, and normal code/data sections.
//!
//! Entropy ranges:
//! - 0.0: uniform (all same byte)
//! - ~4.5-5.5: typical ASCII text
//! - ~6.0-7.0: typical compiled code
//! - >7.0: compressed/encrypted data
//! - 8.0: maximum (perfectly uniform distribution)

use std::path::Path;

use crate::error::{Error, Result};

/// Entropy analysis result for an ELF section.
#[derive(Debug, Clone)]
pub struct SectionEntropy {
    /// Section name.
    pub name: String,
    /// Section virtual address.
    pub addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// Shannon entropy (0.0 - 8.0).
    pub entropy: f64,
}

/// Block-level entropy result.
#[derive(Debug, Clone)]
pub struct BlockEntropy {
    /// Virtual address of the block.
    pub addr: u64,
    /// Shannon entropy of this block.
    pub entropy: f64,
}

/// Compute Shannon entropy for a byte slice.
///
/// Returns a value between 0.0 (all identical bytes) and 8.0
/// (perfectly uniform distribution of all 256 byte values).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Analyze entropy per ELF section.
pub fn analyze_sections(path: &Path) -> Result<Vec<SectionEntropy>> {
    let data =
        std::fs::read(path).map_err(|e| Error::Other(format!("read: {}", e)))?;
    analyze_sections_bytes(&data)
}

/// Analyze entropy per ELF section from raw data.
pub fn analyze_sections_bytes(data: &[u8]) -> Result<Vec<SectionEntropy>> {
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    let mut results = Vec::new();

    for sh in &elf.section_headers {
        if sh.sh_size == 0 {
            continue;
        }

        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if offset + size > data.len() {
            continue;
        }

        let section_data = &data[offset..offset + size];
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("<unknown>")
            .to_string();

        results.push(SectionEntropy {
            name,
            addr: sh.sh_addr,
            size: sh.sh_size,
            entropy: shannon_entropy(section_data),
        });
    }

    Ok(results)
}

/// Compute block-level entropy across a byte slice.
///
/// Divides `data` into blocks of `block_size` bytes and computes
/// Shannon entropy for each block.
pub fn block_entropy(data: &[u8], base_addr: u64, block_size: usize) -> Vec<BlockEntropy> {
    let block_size = if block_size == 0 { 256 } else { block_size };
    let mut results = Vec::new();

    for (i, chunk) in data.chunks(block_size).enumerate() {
        results.push(BlockEntropy {
            addr: base_addr + (i * block_size) as u64,
            entropy: shannon_entropy(chunk),
        });
    }

    results
}

/// Classify entropy into a human-readable category.
pub fn classify_entropy(entropy: f64) -> &'static str {
    if entropy < 0.5 {
        "zeros/padding"
    } else if entropy < 3.0 {
        "low entropy"
    } else if entropy < 5.5 {
        "text/strings"
    } else if entropy < 7.0 {
        "code/data"
    } else if entropy < 7.5 {
        "high entropy"
    } else {
        "packed/encrypted"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_all_zeros() {
        let data = vec![0u8; 256];
        let e = shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.001, "all-zero entropy should be 0.0, got {}", e);
    }

    #[test]
    fn entropy_uniform() {
        // Every byte value appears exactly once
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.001,
            "uniform distribution entropy should be 8.0, got {}",
            e
        );
    }

    #[test]
    fn entropy_ascii_text() {
        let text = b"The quick brown fox jumps over the lazy dog. \
                     This is a sample text to test entropy calculation.";
        let e = shannon_entropy(text);
        assert!(
            e > 3.5 && e < 6.0,
            "ASCII text entropy should be ~4.0-5.5, got {}",
            e
        );
    }

    #[test]
    fn entropy_empty() {
        let e = shannon_entropy(&[]);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn entropy_single_byte() {
        let e = shannon_entropy(&[0x42]);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn entropy_two_values() {
        // Half 0x00, half 0xFF → entropy = 1.0
        let mut data = vec![0x00; 128];
        data.extend_from_slice(&[0xFF; 128]);
        let e = shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.001,
            "two-value entropy should be 1.0, got {}",
            e
        );
    }

    #[test]
    fn block_entropy_basic() {
        let mut data = vec![0u8; 512];
        // Second block: all different values
        for i in 0..256 {
            data[256 + i] = i as u8;
        }
        let blocks = block_entropy(&data, 0x1000, 256);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].entropy < 0.001); // All zeros
        assert!((blocks[1].entropy - 8.0).abs() < 0.001); // Uniform
    }

    #[test]
    fn classify_entropy_ranges() {
        assert_eq!(classify_entropy(0.0), "zeros/padding");
        assert_eq!(classify_entropy(1.0), "low entropy");
        assert_eq!(classify_entropy(4.5), "text/strings");
        assert_eq!(classify_entropy(6.5), "code/data");
        assert_eq!(classify_entropy(7.2), "high entropy");
        assert_eq!(classify_entropy(7.9), "packed/encrypted");
    }
}
