//! glibc heap analysis for exploit development.
//!
//! Parses malloc_chunk, malloc_state (arena), and tcache structures
//! from process memory to inspect heap layout.

use crate::error::{Error, Result};

/// Chunk flag bits in the size field.
pub const PREV_INUSE: u64 = 0x1;
pub const IS_MMAPPED: u64 = 0x2;
pub const NON_MAIN_ARENA: u64 = 0x4;
pub const SIZE_MASK: u64 = !0x7;

/// Number of fastbin slots in glibc.
pub const NFASTBINS: usize = 10;
/// Number of tcache bins.
pub const TCACHE_MAX_BINS: usize = 64;
/// Number of bins in malloc_state.
pub const NBINS: usize = 254;

/// A parsed malloc_chunk header.
#[derive(Debug, Clone)]
pub struct MallocChunk {
    /// Address of the chunk (points to prev_size field).
    pub addr: u64,
    /// Previous chunk size (only valid if PREV_INUSE is clear).
    pub prev_size: u64,
    /// Size field including flag bits.
    pub size_raw: u64,
    /// Actual usable size (size & ~0x7).
    pub size: u64,
    /// PREV_INUSE flag.
    pub prev_inuse: bool,
    /// IS_MMAPPED flag.
    pub is_mmapped: bool,
    /// NON_MAIN_ARENA flag.
    pub non_main_arena: bool,
    /// Forward pointer (for free chunks in bins).
    pub fd: u64,
    /// Backward pointer (for free chunks in bins).
    pub bk: u64,
}

/// A parsed malloc_state (arena) header.
#[derive(Debug, Clone)]
pub struct MallocState {
    /// Address of the arena in memory.
    pub addr: u64,
    /// Fastbin array (NFASTBINS pointers).
    pub fastbins: Vec<u64>,
    /// Top chunk pointer.
    pub top: u64,
    /// Last remainder pointer.
    pub last_remainder: u64,
    /// Bins array (NBINS * 2 pointers, fd/bk pairs).
    pub bins: Vec<u64>,
    /// Total memory allocated via brk.
    pub system_mem: u64,
}

/// A tcache entry (single-linked list node).
#[derive(Debug, Clone)]
pub struct TcacheEntry {
    /// Bin index (0-63).
    pub bin: usize,
    /// Count of entries in this bin.
    pub count: u16,
    /// Head pointer of the linked list.
    pub head: u64,
}

/// A single chunk in a bin's free list.
#[derive(Debug, Clone)]
pub struct BinEntry {
    /// Bin category.
    pub bin_type: BinType,
    /// Bin index.
    pub index: usize,
    /// Chunk address.
    pub chunk_addr: u64,
    /// Chunk size.
    pub chunk_size: u64,
}

/// Classification of bin types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinType {
    Tcache,
    Fast,
    Unsorted,
    Small,
    Large,
}

impl std::fmt::Display for BinType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcache => write!(f, "tcache"),
            Self::Fast => write!(f, "fastbin"),
            Self::Unsorted => write!(f, "unsorted"),
            Self::Small => write!(f, "smallbin"),
            Self::Large => write!(f, "largebin"),
        }
    }
}

/// Parse a malloc_chunk from raw bytes (16 bytes minimum for header).
pub fn parse_chunk(data: &[u8], addr: u64) -> Result<MallocChunk> {
    if data.len() < 16 {
        return Err(Error::Other("chunk data too short (need 16+ bytes)".into()));
    }

    let prev_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let size_raw = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let fd = if data.len() >= 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap())
    } else {
        0
    };
    let bk = if data.len() >= 32 {
        u64::from_le_bytes(data[24..32].try_into().unwrap())
    } else {
        0
    };

    Ok(MallocChunk {
        addr,
        prev_size,
        size_raw,
        size: size_raw & SIZE_MASK,
        prev_inuse: size_raw & PREV_INUSE != 0,
        is_mmapped: size_raw & IS_MMAPPED != 0,
        non_main_arena: size_raw & NON_MAIN_ARENA != 0,
        fd,
        bk,
    })
}

/// Walk a chain of chunks starting from `start_addr`.
///
/// `read_memory` is a callback to read bytes from the target process.
/// Walks until a zero-size chunk, the top chunk, or a safety limit.
pub fn walk_chunks<F>(
    start_addr: u64,
    top_addr: u64,
    read_memory: &F,
    max_chunks: usize,
) -> Result<Vec<MallocChunk>>
where
    F: Fn(u64, usize) -> Result<Vec<u8>>,
{
    let max_chunks = if max_chunks == 0 { 4096 } else { max_chunks };
    let mut chunks = Vec::new();
    let mut addr = start_addr;

    for _ in 0..max_chunks {
        let data = read_memory(addr, 32)?;
        let chunk = parse_chunk(&data, addr)?;

        if chunk.size == 0 || chunk.size > 0x1_0000_0000 {
            break; // Invalid or corrupt chunk
        }

        let is_top = addr == top_addr;
        chunks.push(chunk.clone());

        if is_top {
            break;
        }

        addr += chunk.size;
    }

    Ok(chunks)
}

/// Walk a fastbin linked list.
///
/// Fastbins use single-linked lists via the `fd` field.
pub fn walk_fastbin<F>(
    head: u64,
    read_memory: &F,
    max_entries: usize,
) -> Result<Vec<u64>>
where
    F: Fn(u64, usize) -> Result<Vec<u8>>,
{
    let max_entries = if max_entries == 0 { 256 } else { max_entries };
    let mut entries = Vec::new();
    let mut ptr = head;

    for _ in 0..max_entries {
        if ptr == 0 {
            break;
        }
        entries.push(ptr);
        // Read the fd pointer (at offset 16 = after prev_size + size)
        let data = read_memory(ptr + 16, 8)?;
        ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
    }

    Ok(entries)
}

/// Parse tcache entries from the tcache_perthread_struct.
///
/// Layout: counts[64] as u16 (128 bytes), entries[64] as pointers (512 bytes).
/// Total: 640 bytes.
pub fn parse_tcache(data: &[u8]) -> Result<Vec<TcacheEntry>> {
    if data.len() < 640 {
        return Err(Error::Other(format!(
            "tcache data too short: {} (need 640)",
            data.len()
        )));
    }

    let mut entries = Vec::new();
    for i in 0..TCACHE_MAX_BINS {
        let count =
            u16::from_le_bytes(data[i * 2..i * 2 + 2].try_into().unwrap());
        let head_offset = 128 + i * 8; // After counts array
        let head =
            u64::from_le_bytes(data[head_offset..head_offset + 8].try_into().unwrap());

        if count > 0 || head != 0 {
            entries.push(TcacheEntry {
                bin: i,
                count,
                head,
            });
        }
    }

    Ok(entries)
}

/// Classify a bin index into its type.
pub fn classify_bin(index: usize) -> BinType {
    match index {
        0 => BinType::Unsorted,
        1..=62 => BinType::Small,
        _ => BinType::Large,
    }
}

/// Calculate the chunk size for a given fastbin index.
pub fn fastbin_size(index: usize) -> u64 {
    // Fastbin sizes: 32, 48, 64, 80, 96, 112, 128, 144, 160, 176 (on x86_64)
    (index as u64 + 2) * 16
}

/// Calculate the chunk size for a given tcache bin index.
pub fn tcache_bin_size(index: usize) -> u64 {
    // Tcache sizes: 32, 48, 64, ... (same spacing as fastbins, up to 1040)
    (index as u64 + 2) * 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chunk_basic() {
        // prev_size=0, size=0x91 (PREV_INUSE set, actual size=0x90)
        let mut data = vec![0u8; 32];
        // prev_size = 0
        data[8..16].copy_from_slice(&0x91u64.to_le_bytes());
        // fd
        data[16..24].copy_from_slice(&0xDEAD0000u64.to_le_bytes());
        // bk
        data[24..32].copy_from_slice(&0xBEEF0000u64.to_le_bytes());

        let chunk = parse_chunk(&data, 0x1000).unwrap();
        assert_eq!(chunk.addr, 0x1000);
        assert_eq!(chunk.prev_size, 0);
        assert_eq!(chunk.size_raw, 0x91);
        assert_eq!(chunk.size, 0x90);
        assert!(chunk.prev_inuse);
        assert!(!chunk.is_mmapped);
        assert!(!chunk.non_main_arena);
        assert_eq!(chunk.fd, 0xDEAD0000);
        assert_eq!(chunk.bk, 0xBEEF0000);
    }

    #[test]
    fn parse_chunk_flags() {
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&0x97u64.to_le_bytes()); // size=0x90, all 3 flags set

        let chunk = parse_chunk(&data, 0x2000).unwrap();
        assert_eq!(chunk.size, 0x90);
        assert!(chunk.prev_inuse);
        assert!(chunk.is_mmapped);
        assert!(chunk.non_main_arena);
    }

    #[test]
    fn parse_chunk_too_short() {
        let data = vec![0u8; 8];
        assert!(parse_chunk(&data, 0).is_err());
    }

    #[test]
    fn fastbin_sizes() {
        assert_eq!(fastbin_size(0), 32);
        assert_eq!(fastbin_size(1), 48);
        assert_eq!(fastbin_size(2), 64);
        assert_eq!(fastbin_size(9), 176);
    }

    #[test]
    fn tcache_sizes() {
        assert_eq!(tcache_bin_size(0), 32);
        assert_eq!(tcache_bin_size(1), 48);
        assert_eq!(tcache_bin_size(63), 1040);
    }

    #[test]
    fn classify_bins() {
        assert_eq!(classify_bin(0), BinType::Unsorted);
        assert_eq!(classify_bin(1), BinType::Small);
        assert_eq!(classify_bin(62), BinType::Small);
        assert_eq!(classify_bin(63), BinType::Large);
    }

    #[test]
    fn parse_tcache_basic() {
        let mut data = vec![0u8; 640];
        // Set bin 0: count=2, head=0x5555_0000
        data[0..2].copy_from_slice(&2u16.to_le_bytes());
        data[128..136].copy_from_slice(&0x5555_0000u64.to_le_bytes());
        // Set bin 5: count=1, head=0x6666_0000
        data[10..12].copy_from_slice(&1u16.to_le_bytes());
        data[168..176].copy_from_slice(&0x6666_0000u64.to_le_bytes());

        let entries = parse_tcache(&data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].bin, 0);
        assert_eq!(entries[0].count, 2);
        assert_eq!(entries[0].head, 0x5555_0000);
        assert_eq!(entries[1].bin, 5);
        assert_eq!(entries[1].count, 1);
    }

    #[test]
    fn walk_chunks_basic() {
        // Create two chunks: first at 0x1000 (size 0x40), second at 0x1040 (size 0x40, top)
        let read_memory = |addr: u64, len: usize| -> Result<Vec<u8>> {
            let mut data = vec![0u8; len];
            match addr {
                0x1000 => {
                    if len >= 16 {
                        data[8..16].copy_from_slice(&0x41u64.to_le_bytes());
                    }
                }
                0x1040 => {
                    if len >= 16 {
                        data[8..16].copy_from_slice(&0x41u64.to_le_bytes());
                    }
                }
                _ => {}
            }
            Ok(data)
        };

        let chunks = walk_chunks(0x1000, 0x1040, &read_memory, 100).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].addr, 0x1000);
        assert_eq!(chunks[0].size, 0x40);
        assert_eq!(chunks[1].addr, 0x1040);
    }
}
