//! Linux procfs utilities for inspecting tracee state.
//!
//! Corresponds to book Ch.4 (Pipes, procfs, and Automated Testing).
//!
//! Provides access to `/proc/[pid]/maps`, `/proc/[pid]/status`,
//! and other procfs entries useful for debugging.

use nix::unistd::Pid;
use std::path::PathBuf;

use crate::error::Result;
use crate::types::VirtAddr;

/// A single memory region from `/proc/[pid]/maps`.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub perms: Permissions,
    pub offset: u64,
    pub pathname: String,
}

/// Memory region permissions (rwxp/s).
#[derive(Debug, Clone, Copy)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub private: bool,
}

impl std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.private { 'p' } else { 's' },
        )
    }
}

/// Parse `/proc/[pid]/maps` into a list of memory regions.
pub fn read_memory_maps(pid: Pid) -> Result<Vec<MemoryRegion>> {
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    Ok(parse_maps(&content))
}

/// Parse the contents of a maps file.
///
/// Separated from `read_memory_maps` for testability.
pub fn parse_maps(content: &str) -> Vec<MemoryRegion> {
    content.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MemoryRegion> {
    // Format: 7f8a1000-7f8a2000 r-xp 00000000 08:01 12345  /lib/libc.so.6
    let mut parts = line.splitn(6, char::is_whitespace);

    let addr_range = parts.next()?;
    let perms_str = parts.next()?;
    let offset_str = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let pathname = parts.next().unwrap_or("").trim().to_string();

    let (start_str, end_str) = addr_range.split_once('-')?;
    let perms = perms_str.as_bytes();
    if perms.len() < 4 {
        return None;
    }

    Some(MemoryRegion {
        start: VirtAddr(u64::from_str_radix(start_str, 16).ok()?),
        end: VirtAddr(u64::from_str_radix(end_str, 16).ok()?),
        perms: Permissions {
            read: perms[0] == b'r',
            write: perms[1] == b'w',
            execute: perms[2] == b'x',
            private: perms[3] == b'p',
        },
        offset: u64::from_str_radix(offset_str, 16).ok()?,
        pathname,
    })
}

/// Get the executable path for a process via `/proc/[pid]/exe`.
pub fn get_exe_path(pid: Pid) -> Result<PathBuf> {
    let path = std::fs::read_link(format!("/proc/{}/exe", pid))?;
    Ok(path)
}

/// Find the base load address of a binary in the process's memory map.
///
/// For PIE executables, the actual load address differs from the
/// addresses in the ELF file. This function finds the first executable
/// mapping of the given binary to determine the load bias.
pub fn find_load_address(maps: &[MemoryRegion], binary_path: &str) -> Option<VirtAddr> {
    maps.iter()
        .find(|r| r.perms.execute && r.pathname.ends_with(binary_path))
        .map(|r| r.start)
}

/// Find which memory region contains a given address.
pub fn find_region_containing(maps: &[MemoryRegion], addr: VirtAddr) -> Option<&MemoryRegion> {
    maps.iter().find(|r| addr >= r.start && addr < r.end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAPS: &str = "\
564756400000-564756401000 r--p 00000000 08:01 1234567  /usr/bin/hello
564756401000-564756402000 r-xp 00001000 08:01 1234567  /usr/bin/hello
564756402000-564756403000 r--p 00002000 08:01 1234567  /usr/bin/hello
564756403000-564756404000 r--p 00002000 08:01 1234567  /usr/bin/hello
564756404000-564756405000 rw-p 00003000 08:01 1234567  /usr/bin/hello
7f8a12000000-7f8a12022000 r--p 00000000 08:01 2345678  /usr/lib/x86_64-linux-gnu/libc.so.6
7f8a12022000-7f8a121b7000 r-xp 00022000 08:01 2345678  /usr/lib/x86_64-linux-gnu/libc.so.6
7ffd5e371000-7ffd5e392000 rw-p 00000000 00:00 0        [stack]
7ffd5e3f2000-7ffd5e3f6000 r--p 00000000 00:00 0        [vvar]
7ffd5e3f6000-7ffd5e3f8000 r-xp 00000000 00:00 0        [vdso]";

    #[test]
    fn parse_maps_basic() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(regions.len(), 10);
    }

    #[test]
    fn parse_maps_addresses() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(regions[0].start, VirtAddr(0x564756400000));
        assert_eq!(regions[0].end, VirtAddr(0x564756401000));
    }

    #[test]
    fn parse_maps_permissions() {
        let regions = parse_maps(SAMPLE_MAPS);
        // r--p
        assert!(regions[0].perms.read);
        assert!(!regions[0].perms.write);
        assert!(!regions[0].perms.execute);
        assert!(regions[0].perms.private);
        // r-xp
        assert!(regions[1].perms.execute);
        // rw-p
        assert!(regions[4].perms.write);
        assert!(!regions[4].perms.execute);
    }

    #[test]
    fn parse_maps_pathnames() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(regions[0].pathname, "/usr/bin/hello");
        assert_eq!(regions[8].pathname, "[vvar]");
        assert_eq!(regions[7].pathname, "[stack]");
    }

    #[test]
    fn find_load_address_works() {
        let regions = parse_maps(SAMPLE_MAPS);
        let addr = find_load_address(&regions, "/usr/bin/hello");
        // First executable mapping of hello
        assert_eq!(addr, Some(VirtAddr(0x564756401000)));
    }

    #[test]
    fn find_load_address_not_found() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert_eq!(find_load_address(&regions, "/nonexistent"), None);
    }

    #[test]
    fn find_region_containing_works() {
        let regions = parse_maps(SAMPLE_MAPS);
        let region = find_region_containing(&regions, VirtAddr(0x564756401500));
        assert!(region.is_some());
        assert_eq!(region.unwrap().pathname, "/usr/bin/hello");
        assert!(region.unwrap().perms.execute);
    }

    #[test]
    fn find_region_containing_none() {
        let regions = parse_maps(SAMPLE_MAPS);
        assert!(find_region_containing(&regions, VirtAddr(0x1000)).is_none());
    }

    #[test]
    fn permissions_display() {
        let perms = Permissions {
            read: true,
            write: false,
            execute: true,
            private: true,
        };
        assert_eq!(format!("{}", perms), "r-xp");
    }
}
