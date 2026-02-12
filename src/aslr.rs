//! ASLR/PIE leak calculator and libc offset database.
//!
//! Helpers for computing base addresses from information leaks,
//! partial overwrite analysis, and libc version identification.

use crate::error::{Error, Result};
use std::collections::HashMap;

/// ASLR/PIE base address calculator.
///
/// Tracks computed base addresses for different memory regions
/// (e.g., "binary", "libc", "heap") and resolves symbol addresses.
#[derive(Debug, Clone)]
pub struct AslrCalculator {
    /// Known symbol offsets: name -> file offset.
    known_offsets: HashMap<String, u64>,
    /// Computed base addresses: region -> base.
    bases: HashMap<String, u64>,
}

impl AslrCalculator {
    pub fn new() -> Self {
        Self {
            known_offsets: HashMap::new(),
            bases: HashMap::new(),
        }
    }

    /// Calculate base address from a leaked runtime address and known offset.
    ///
    /// `region` is a label like "libc" or "binary".
    /// `leaked_addr` is the runtime address observed.
    /// `offset` is the known file offset of the leaked symbol.
    pub fn calc_base(&mut self, region: &str, leaked_addr: u64, offset: u64) -> u64 {
        let base = leaked_addr.wrapping_sub(offset);
        self.bases.insert(region.to_string(), base);
        base
    }

    /// Get the stored base address for a region.
    pub fn get_base(&self, region: &str) -> Option<u64> {
        self.bases.get(region).copied()
    }

    /// Calculate a runtime address given a stored base and offset.
    pub fn calc_addr(&self, region: &str, offset: u64) -> Option<u64> {
        self.bases.get(region).map(|base| base.wrapping_add(offset))
    }

    /// Register a known symbol offset for later resolution.
    pub fn add_offset(&mut self, name: &str, offset: u64) {
        self.known_offsets.insert(name.to_string(), offset);
    }

    /// Resolve a symbol's runtime address using stored base and offset.
    pub fn resolve(&self, region: &str, name: &str) -> Option<u64> {
        let base = self.bases.get(region)?;
        let offset = self.known_offsets.get(name)?;
        Some(base.wrapping_add(*offset))
    }

    /// List all computed bases.
    pub fn all_bases(&self) -> &HashMap<String, u64> {
        &self.bases
    }

    /// Validate that a leaked address looks like a valid x86_64 userspace pointer.
    pub fn validate_leak(addr: u64) -> bool {
        addr > 0x1000 && addr < 0x0000_8000_0000_0000
    }

    /// Check if an address is page-aligned (4096-byte boundary).
    pub fn is_page_aligned(addr: u64) -> bool {
        addr & 0xFFF == 0
    }

    /// Extract the page offset (low 12 bits) from an address.
    pub fn page_offset(addr: u64) -> u64 {
        addr & 0xFFF
    }
}

/// Result of partial overwrite analysis.
#[derive(Debug, Clone)]
pub struct PartialOverwrite {
    /// Number of bytes being overwritten.
    pub overwrite_bytes: usize,
    /// The byte values to write (little-endian).
    pub payload: Vec<u8>,
    /// Number of random ASLR bits within the overwrite region.
    pub random_bits: u32,
    /// Probability of success per attempt (1.0 = deterministic).
    pub success_probability: f64,
    /// Expected number of attempts needed.
    pub expected_attempts: u64,
}

/// Analyze a partial overwrite scenario.
///
/// Given a target address and how many bytes we can overwrite,
/// compute the payload and probability of success under ASLR.
pub fn partial_overwrite(target_addr: u64, overwrite_bytes: usize) -> PartialOverwrite {
    assert!((1..=8).contains(&overwrite_bytes));

    let mask = if overwrite_bytes >= 8 {
        u64::MAX
    } else {
        (1u64 << (overwrite_bytes * 8)) - 1
    };

    let payload_value = target_addr & mask;
    let payload = payload_value.to_le_bytes()[..overwrite_bytes].to_vec();

    // ASLR randomizes page-aligned bases, so low 12 bits are fixed.
    // For an N-byte overwrite controlling bits 0..(N*8-1):
    // - Bits 0..11 are deterministic (page offset)
    // - Bits 12..(N*8-1) are random
    let controlled_bits = (overwrite_bytes * 8) as u32;
    let random_bits = controlled_bits.saturating_sub(12);

    let success_probability = if random_bits == 0 {
        1.0
    } else {
        1.0 / (1u64 << random_bits) as f64
    };
    let expected_attempts = if random_bits == 0 { 1 } else { 1u64 << random_bits };

    PartialOverwrite {
        overwrite_bytes,
        payload,
        random_bits,
        success_probability,
        expected_attempts,
    }
}

/// Calculate all possible base addresses from a partial address leak.
///
/// `partial_leak`: the known low bytes of a runtime address.
/// `n_bytes`: how many bytes of the address are known (1-6).
/// `offset`: the known file offset of the leaked symbol.
pub fn brute_force_bases(partial_leak: u64, n_bytes: usize, offset: u64) -> Vec<u64> {
    assert!((1..=6).contains(&n_bytes));

    let known_mask = (1u64 << (n_bytes * 8)) - 1;
    let known_low = partial_leak & known_mask;
    let step = 1u64 << (n_bytes * 8);

    let mut bases = Vec::new();
    let mut addr = known_low;
    while addr < 0x0000_8000_0000_0000 {
        let base = addr.wrapping_sub(offset);
        if AslrCalculator::is_page_aligned(base) && base < 0x0000_8000_0000_0000 {
            bases.push(base);
        }
        addr = match addr.checked_add(step) {
            Some(a) => a,
            None => break,
        };
    }
    bases
}

/// Convenience: calculate base from a leaked function address.
pub fn base_from_leak(leaked_func: u64, func_offset: u64) -> u64 {
    leaked_func.wrapping_sub(func_offset)
}

/// A libc version entry with known symbol offsets.
#[derive(Debug, Clone)]
pub struct LibcVersion {
    /// Human-readable identifier (e.g., "libc-2.35-ubuntu22.04").
    pub id: String,
    /// BuildID hex string (from ELF .note.gnu.build-id).
    pub build_id: String,
    /// Symbol name -> file offset.
    pub symbols: HashMap<String, u64>,
}

/// In-memory libc offset database.
pub struct LibcDb {
    versions: Vec<LibcVersion>,
}

impl LibcDb {
    /// Create an empty database.
    pub fn new() -> Self {
        Self { versions: Vec::new() }
    }

    /// Add a libc version entry.
    pub fn add_version(&mut self, version: LibcVersion) {
        self.versions.push(version);
    }

    /// Look up a libc version by BuildID.
    pub fn lookup_by_build_id(&self, build_id: &str) -> Option<&LibcVersion> {
        self.versions.iter().find(|v| v.build_id == build_id)
    }

    /// Identify libc versions by matching the low 12 bits of a leaked symbol address.
    ///
    /// ASLR randomizes page-aligned bases, so the low 12 bits of any
    /// symbol's runtime address equal the low 12 bits of its file offset.
    pub fn identify_by_leak(&self, symbol_name: &str, leaked_addr: u64) -> Vec<&LibcVersion> {
        let low12 = leaked_addr & 0xFFF;
        self.versions
            .iter()
            .filter(|v| {
                v.symbols
                    .get(symbol_name)
                    .map(|off| off & 0xFFF == low12)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Number of entries in the database.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Extract symbol offsets from an ELF's dynamic symbol table.
    pub fn extract_offsets(data: &[u8]) -> Result<HashMap<String, u64>> {
        let elf = goblin::elf::Elf::parse(data)
            .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;
        let mut offsets = HashMap::new();
        for sym in &elf.dynsyms {
            if sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        offsets.insert(name.to_string(), sym.st_value);
                    }
                }
            }
        }
        Ok(offsets)
    }

    /// Extract BuildID from ELF .note.gnu.build-id section.
    pub fn extract_build_id(data: &[u8]) -> Result<String> {
        let elf = goblin::elf::Elf::parse(data)
            .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".note.gnu.build-id" {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if offset + size > data.len() || size < 16 {
                    continue;
                }
                let note_data = &data[offset..offset + size];
                let namesz = u32::from_le_bytes(note_data[0..4].try_into().unwrap()) as usize;
                let descsz = u32::from_le_bytes(note_data[4..8].try_into().unwrap()) as usize;
                let name_aligned = (namesz + 3) & !3;
                let desc_start = 12 + name_aligned;
                if desc_start + descsz <= note_data.len() {
                    let build_id = &note_data[desc_start..desc_start + descsz];
                    return Ok(build_id.iter().map(|b| format!("{:02x}", b)).collect());
                }
            }
        }
        Err(Error::Other("BuildID not found".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_base_simple() {
        let mut calc = AslrCalculator::new();
        let base = calc.calc_base("libc", 0x7f0000100aa0, 0xaa0);
        assert_eq!(base, 0x7f0000100000);
        assert!(AslrCalculator::is_page_aligned(base));
    }

    #[test]
    fn calc_addr_roundtrip() {
        let mut calc = AslrCalculator::new();
        calc.calc_base("libc", 0x7f0000100aa0, 0xaa0);
        let addr = calc.calc_addr("libc", 0x50d70).unwrap();
        assert_eq!(addr, 0x7f0000100000 + 0x50d70);
    }

    #[test]
    fn resolve_symbol() {
        let mut calc = AslrCalculator::new();
        calc.calc_base("libc", 0x7f0000100aa0, 0xaa0);
        calc.add_offset("system", 0x50d70);
        let addr = calc.resolve("libc", "system").unwrap();
        assert_eq!(addr, 0x7f0000150d70);
    }

    #[test]
    fn resolve_missing_returns_none() {
        let calc = AslrCalculator::new();
        assert!(calc.resolve("libc", "system").is_none());
    }

    #[test]
    fn validate_leak_values() {
        assert!(!AslrCalculator::validate_leak(0));
        assert!(!AslrCalculator::validate_leak(0x100));
        assert!(AslrCalculator::validate_leak(0x400000));
        assert!(AslrCalculator::validate_leak(0x7f0000000000));
        assert!(!AslrCalculator::validate_leak(0xffff800000000000)); // kernel
    }

    #[test]
    fn page_alignment_check() {
        assert!(AslrCalculator::is_page_aligned(0x400000));
        assert!(AslrCalculator::is_page_aligned(0x7f0000100000));
        assert!(!AslrCalculator::is_page_aligned(0x400001));
        assert!(!AslrCalculator::is_page_aligned(0x400aa0));
    }

    #[test]
    fn page_offset_extraction() {
        assert_eq!(AslrCalculator::page_offset(0x7f00001050d0), 0x0d0);
        assert_eq!(AslrCalculator::page_offset(0x400000), 0);
    }

    #[test]
    fn partial_overwrite_1byte() {
        let po = partial_overwrite(0x7f0000100060, 1);
        assert_eq!(po.payload, vec![0x60]);
        assert_eq!(po.random_bits, 0); // 8 bits, all within page offset
        assert_eq!(po.success_probability, 1.0);
        assert_eq!(po.expected_attempts, 1);
    }

    #[test]
    fn partial_overwrite_2byte() {
        let po = partial_overwrite(0x7f0000101060, 2);
        assert_eq!(po.payload, vec![0x60, 0x10]); // low 16 bits of 0x1060
        assert_eq!(po.random_bits, 4); // bits 12-15 are random
        assert_eq!(po.expected_attempts, 16);
    }

    #[test]
    fn brute_force_bases_small_leak() {
        // 2-byte leak of puts address (low 16 bits = 0x0aa0, offset = 0x80aa0)
        let bases = brute_force_bases(0x0aa0, 2, 0x80aa0);
        // All bases should be page-aligned
        for base in &bases {
            assert!(AslrCalculator::is_page_aligned(*base));
        }
        assert!(!bases.is_empty());
    }

    #[test]
    fn base_from_leak_convenience() {
        let base = base_from_leak(0x7f00001050d0, 0x50d0);
        assert_eq!(base, 0x7f0000100000);
    }

    #[test]
    fn libc_db_identify_by_leak() {
        let mut db = LibcDb::new();
        let mut syms = HashMap::new();
        syms.insert("puts".to_string(), 0x80aa0u64);
        syms.insert("system".to_string(), 0x50d70u64);
        db.add_version(LibcVersion {
            id: "test-libc".into(),
            build_id: "abc123".into(),
            symbols: syms,
        });

        // Leaked puts address with matching low 12 bits
        let matches = db.identify_by_leak("puts", 0x7f00001800aa0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "test-libc");

        // Non-matching low 12 bits
        let matches = db.identify_by_leak("puts", 0x7f0000180bbb);
        assert!(matches.is_empty());
    }

    #[test]
    fn libc_db_build_id_lookup() {
        let mut db = LibcDb::new();
        db.add_version(LibcVersion {
            id: "test".into(),
            build_id: "deadbeef".into(),
            symbols: HashMap::new(),
        });
        assert!(db.lookup_by_build_id("deadbeef").is_some());
        assert!(db.lookup_by_build_id("00000000").is_none());
    }
}
