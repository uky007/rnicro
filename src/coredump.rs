//! ELF core dump generation.
//!
//! Generates ELF core files from a stopped traced process,
//! capturing registers, memory, and mapped file information.

use crate::error::{Error, Result};

// ── ELF constants ──────────────────────────────────────────────────

const ELFMAG: &[u8] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const PT_NOTE: u32 = 4;
const PT_LOAD: u32 = 1;

const ELF64_EHDR_SIZE: u16 = 64;
const ELF64_PHDR_SIZE: u16 = 56;

// Note types
const NT_PRSTATUS: u32 = 1;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x46494c45;

/// Permissions flags for PT_LOAD segments.
pub const PF_R: u32 = 0x4;
pub const PF_W: u32 = 0x2;
pub const PF_X: u32 = 0x1;

/// Information needed to generate a core dump.
pub struct CoreDumpInfo {
    /// Register values (x86_64 user_regs_struct order, 27 u64 values).
    pub registers: Vec<u64>,
    /// Signal number that caused the stop.
    pub signal: u32,
    /// PID of the process.
    pub pid: u32,
    /// Memory mappings to include.
    pub mappings: Vec<CoreMapping>,
    /// Auxiliary vector bytes.
    pub auxv: Vec<u8>,
}

/// A memory mapping for the core dump.
pub struct CoreMapping {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address.
    pub end: u64,
    /// Permission flags (PF_R | PF_W | PF_X).
    pub flags: u32,
    /// Memory contents.
    pub data: Vec<u8>,
    /// Mapped file path (empty for anonymous).
    pub pathname: String,
    /// File offset.
    pub file_offset: u64,
}

/// Serialize an ELF64 header for a core dump.
pub fn serialize_elf_header(phnum: u16, phoff: u64) -> Vec<u8> {
    let mut hdr = vec![0u8; ELF64_EHDR_SIZE as usize];

    // e_ident
    hdr[0..4].copy_from_slice(ELFMAG);
    hdr[4] = ELFCLASS64;
    hdr[5] = ELFDATA2LSB;
    hdr[6] = EV_CURRENT;
    hdr[7] = ELFOSABI_NONE;

    // e_type = ET_CORE
    hdr[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
    // e_machine = EM_X86_64
    hdr[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    // e_version
    hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry = 0
    // e_phoff
    hdr[32..40].copy_from_slice(&phoff.to_le_bytes());
    // e_shoff = 0
    // e_flags = 0
    // e_ehsize
    hdr[52..54].copy_from_slice(&ELF64_EHDR_SIZE.to_le_bytes());
    // e_phentsize
    hdr[54..56].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    // e_phnum
    hdr[56..58].copy_from_slice(&phnum.to_le_bytes());
    // e_shentsize
    hdr[58..60].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    // e_shnum = 0
    // e_shstrndx = 0

    hdr
}

/// Serialize an ELF64 program header.
pub fn serialize_phdr(
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
) -> Vec<u8> {
    let mut phdr = vec![0u8; ELF64_PHDR_SIZE as usize];

    phdr[0..4].copy_from_slice(&p_type.to_le_bytes());
    phdr[4..8].copy_from_slice(&p_flags.to_le_bytes());
    phdr[8..16].copy_from_slice(&p_offset.to_le_bytes());
    phdr[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
    // p_paddr = p_vaddr
    phdr[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
    phdr[32..40].copy_from_slice(&p_filesz.to_le_bytes());
    phdr[40..48].copy_from_slice(&p_memsz.to_le_bytes());
    // p_align = 0 (for core dumps)

    phdr
}

/// Serialize an ELF note entry.
pub fn serialize_note(name: &[u8], note_type: u32, desc: &[u8]) -> Vec<u8> {
    let namesz = name.len() as u32;
    let descsz = desc.len() as u32;
    let name_aligned = align4(name.len());
    let desc_aligned = align4(desc.len());

    let total = 12 + name_aligned + desc_aligned;
    let mut note = vec![0u8; total];

    note[0..4].copy_from_slice(&namesz.to_le_bytes());
    note[4..8].copy_from_slice(&descsz.to_le_bytes());
    note[8..12].copy_from_slice(&note_type.to_le_bytes());
    note[12..12 + name.len()].copy_from_slice(name);
    let desc_off = 12 + name_aligned;
    note[desc_off..desc_off + desc.len()].copy_from_slice(desc);

    note
}

/// Build the NT_PRSTATUS note descriptor.
///
/// Simplified prstatus: signal info + register set.
/// The register set is the user_regs_struct (27 * 8 = 216 bytes).
pub fn build_prstatus(signal: u32, pid: u32, registers: &[u64]) -> Vec<u8> {
    // Simplified elf_prstatus layout (total ~336 bytes):
    // Offset 0: si_signo (4), si_code (4), si_errno (4) = 12 bytes
    // Offset 12: pr_cursig (2), padding (2) = 4 bytes
    // Offset 16: pr_sigpend (8), pr_sighold (8) = 16 bytes
    // Offset 32: pr_pid (4), pr_ppid (4), pr_pgrp (4), pr_sid (4) = 16 bytes
    // Offset 48: pr_utime (16), pr_stime (16), pr_cutime (16), pr_cstime (16) = 64 bytes
    // Offset 112: pr_reg (27 * 8 = 216 bytes)
    // Offset 328: pr_fpvalid (4) = 4 bytes
    // Total: 332 bytes
    let mut desc = vec![0u8; 332];

    // si_signo
    desc[0..4].copy_from_slice(&signal.to_le_bytes());
    // pr_cursig
    desc[12..14].copy_from_slice(&(signal as u16).to_le_bytes());
    // pr_pid
    desc[32..36].copy_from_slice(&pid.to_le_bytes());

    // pr_reg: copy register values
    let reg_offset = 112;
    for (i, &val) in registers.iter().enumerate().take(27) {
        let off = reg_offset + i * 8;
        desc[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    desc
}

/// Build the NT_FILE note descriptor from mapped file information.
pub fn build_file_note(mappings: &[(u64, u64, u64, &str)]) -> Vec<u8> {
    // Filter to only file-backed mappings
    let file_mappings: Vec<_> = mappings.iter().filter(|(_, _, _, p)| !p.is_empty()).collect();

    let count = file_mappings.len() as u64;
    let page_size: u64 = 4096;

    // Header: count (8) + page_size (8)
    let mut desc = Vec::new();
    desc.extend_from_slice(&count.to_le_bytes());
    desc.extend_from_slice(&page_size.to_le_bytes());

    // Per-file entries: start (8) + end (8) + offset_in_pages (8)
    for (start, end, offset, _) in &file_mappings {
        desc.extend_from_slice(&start.to_le_bytes());
        desc.extend_from_slice(&end.to_le_bytes());
        desc.extend_from_slice(&(offset / page_size).to_le_bytes());
    }

    // File names (NUL-terminated)
    for (_, _, _, pathname) in &file_mappings {
        desc.extend_from_slice(pathname.as_bytes());
        desc.push(0);
    }

    desc
}

/// Generate a complete ELF core dump.
///
/// Returns the serialized bytes of the core file.
pub fn generate(info: &CoreDumpInfo) -> Result<Vec<u8>> {
    let num_load = info.mappings.len();
    let phnum = 1 + num_load; // PT_NOTE + PT_LOAD per mapping

    if phnum > u16::MAX as usize {
        return Err(Error::Other("too many segments for core dump".into()));
    }

    // Build notes
    let prstatus_desc = build_prstatus(info.signal, info.pid, &info.registers);
    let prstatus_note = serialize_note(b"CORE\0", NT_PRSTATUS, &prstatus_desc);

    let file_mappings: Vec<(u64, u64, u64, &str)> = info
        .mappings
        .iter()
        .map(|m| (m.start, m.end, m.file_offset, m.pathname.as_str()))
        .collect();
    let file_note = serialize_note(b"CORE\0", NT_FILE, &build_file_note(&file_mappings));

    let auxv_note = if !info.auxv.is_empty() {
        serialize_note(b"CORE\0", NT_AUXV, &info.auxv)
    } else {
        Vec::new()
    };

    let notes_data: Vec<u8> = [&prstatus_note[..], &file_note[..], &auxv_note[..]].concat();

    // Calculate layout
    let ehdr_size = ELF64_EHDR_SIZE as u64;
    let phdr_total = phnum as u64 * ELF64_PHDR_SIZE as u64;
    let notes_offset = ehdr_size + phdr_total;
    let notes_size = notes_data.len() as u64;

    // Data offset starts after notes (aligned to 4096 for PT_LOAD)
    let mut data_offset = align_page(notes_offset + notes_size);

    // Build program headers
    let mut phdrs = Vec::new();

    // PT_NOTE
    phdrs.push(serialize_phdr(
        PT_NOTE,
        0,
        notes_offset,
        0,
        notes_size,
        0,
    ));

    // PT_LOAD for each mapping
    let mut load_offsets = Vec::new();
    for mapping in &info.mappings {
        let size = mapping.data.len() as u64;
        let memsz = mapping.end - mapping.start;
        phdrs.push(serialize_phdr(
            PT_LOAD,
            mapping.flags,
            data_offset,
            mapping.start,
            size,
            memsz,
        ));
        load_offsets.push(data_offset);
        data_offset = align_page(data_offset + size);
    }

    // Assemble the core dump
    let mut core = Vec::new();

    // ELF header
    core.extend_from_slice(&serialize_elf_header(phnum as u16, ehdr_size));

    // Program headers
    for phdr in &phdrs {
        core.extend_from_slice(phdr);
    }

    // Notes (pad to offset)
    while core.len() < notes_offset as usize {
        core.push(0);
    }
    core.extend_from_slice(&notes_data);

    // Memory data
    for (i, mapping) in info.mappings.iter().enumerate() {
        let target_offset = load_offsets[i] as usize;
        while core.len() < target_offset {
            core.push(0);
        }
        core.extend_from_slice(&mapping.data);
    }

    Ok(core)
}

/// Align a value up to 4-byte boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Align a value up to page boundary (4096).
fn align_page(n: u64) -> u64 {
    (n + 4095) & !4095
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_header_format() {
        let hdr = serialize_elf_header(3, 64);
        assert_eq!(&hdr[0..4], ELFMAG);
        assert_eq!(hdr[4], ELFCLASS64);
        assert_eq!(hdr[5], ELFDATA2LSB);
        assert_eq!(u16::from_le_bytes([hdr[16], hdr[17]]), ET_CORE);
        assert_eq!(u16::from_le_bytes([hdr[18], hdr[19]]), EM_X86_64);
        assert_eq!(u16::from_le_bytes([hdr[56], hdr[57]]), 3); // phnum
    }

    #[test]
    fn phdr_format() {
        let phdr = serialize_phdr(PT_LOAD, PF_R | PF_W, 0x1000, 0x400000, 0x2000, 0x3000);
        assert_eq!(
            u32::from_le_bytes(phdr[0..4].try_into().unwrap()),
            PT_LOAD
        );
        assert_eq!(
            u32::from_le_bytes(phdr[4..8].try_into().unwrap()),
            PF_R | PF_W
        );
        assert_eq!(
            u64::from_le_bytes(phdr[8..16].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u64::from_le_bytes(phdr[16..24].try_into().unwrap()),
            0x400000
        );
    }

    #[test]
    fn note_serialization() {
        let note = serialize_note(b"CORE\0", NT_PRSTATUS, &[1, 2, 3, 4]);
        let namesz = u32::from_le_bytes(note[0..4].try_into().unwrap());
        let descsz = u32::from_le_bytes(note[4..8].try_into().unwrap());
        let ntype = u32::from_le_bytes(note[8..12].try_into().unwrap());
        assert_eq!(namesz, 5); // "CORE\0"
        assert_eq!(descsz, 4);
        assert_eq!(ntype, NT_PRSTATUS);
    }

    #[test]
    fn prstatus_has_registers() {
        let regs = vec![0x1234u64; 27];
        let desc = build_prstatus(11, 1000, &regs);
        // Check signal
        assert_eq!(u32::from_le_bytes(desc[0..4].try_into().unwrap()), 11);
        // Check pid
        assert_eq!(u32::from_le_bytes(desc[32..36].try_into().unwrap()), 1000);
        // Check first register
        assert_eq!(
            u64::from_le_bytes(desc[112..120].try_into().unwrap()),
            0x1234
        );
    }

    #[test]
    fn file_note_empty() {
        let note = build_file_note(&[]);
        let count = u64::from_le_bytes(note[0..8].try_into().unwrap());
        assert_eq!(count, 0);
    }

    #[test]
    fn align4_works() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    #[test]
    fn generate_minimal_core() {
        let info = CoreDumpInfo {
            registers: vec![0; 27],
            signal: 11,
            pid: 1234,
            mappings: vec![CoreMapping {
                start: 0x400000,
                end: 0x401000,
                flags: PF_R | PF_X,
                data: vec![0x90; 64], // Some NOP bytes
                pathname: String::new(),
                file_offset: 0,
            }],
            auxv: Vec::new(),
        };
        let core = generate(&info).unwrap();
        // Verify ELF magic
        assert_eq!(&core[0..4], ELFMAG);
        // Verify it's a core file
        assert_eq!(u16::from_le_bytes([core[16], core[17]]), ET_CORE);
    }
}
