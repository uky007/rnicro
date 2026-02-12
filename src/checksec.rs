//! Security mechanism analysis for ELF binaries (checksec).
//!
//! Checks for common exploit mitigations: RELRO, NX, PIE,
//! stack canary, and FORTIFY_SOURCE.

use std::fmt;
use std::path::Path;

use crate::error::{Error, Result};

/// Security feature status (for features with partial states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    /// Feature is fully enabled.
    Full,
    /// Feature is partially enabled.
    Partial,
    /// Feature is not enabled.
    None,
}

impl fmt::Display for SecurityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityStatus::Full => write!(f, "Full"),
            SecurityStatus::Partial => write!(f, "Partial"),
            SecurityStatus::None => write!(f, "None"),
        }
    }
}

/// Results of a security feature check on an ELF binary.
#[derive(Debug, Clone)]
pub struct ChecksecResult {
    /// RELRO (Relocation Read-Only): Full, Partial, or None.
    pub relro: SecurityStatus,
    /// Stack canary detected (__stack_chk_fail in dynamic symbols).
    pub canary: bool,
    /// NX (non-executable stack) enabled.
    pub nx: bool,
    /// Position Independent Executable.
    pub pie: bool,
    /// FORTIFY_SOURCE detected (*_chk functions in dynamic symbols).
    pub fortify: bool,
    /// RUNPATH present (can be used for library injection).
    pub runpath: bool,
    /// RPATH present (can be used for library injection).
    pub rpath: bool,
}

/// Analyze an ELF binary at the given path for security mechanisms.
pub fn checksec(path: &Path) -> Result<ChecksecResult> {
    let data = std::fs::read(path)
        .map_err(|e| Error::Other(format!("read ELF '{}': {}", path.display(), e)))?;
    checksec_bytes(&data)
}

/// Analyze ELF binary data for security mechanisms.
pub fn checksec_bytes(data: &[u8]) -> Result<ChecksecResult> {
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    // --- RELRO ---
    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);

    let has_bind_now = elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns.iter().any(|dyn_entry| {
                dyn_entry.d_tag == goblin::elf::dynamic::DT_BIND_NOW
                    || (dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS
                        && dyn_entry.d_val & goblin::elf::dynamic::DF_BIND_NOW != 0)
                    || (dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS_1
                        && dyn_entry.d_val & goblin::elf::dynamic::DF_1_NOW != 0)
            })
        })
        .unwrap_or(false);

    let relro = if has_relro && has_bind_now {
        SecurityStatus::Full
    } else if has_relro {
        SecurityStatus::Partial
    } else {
        SecurityStatus::None
    };

    // --- NX (non-executable stack) ---
    let nx = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK)
        .map(|ph| ph.p_flags & goblin::elf::program_header::PF_X == 0)
        .unwrap_or(true); // No PT_GNU_STACK usually means NX on modern kernels

    // --- PIE ---
    let pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    // --- Stack canary ---
    let canary = elf.dynsyms.iter().any(|sym| {
        elf.dynstrtab
            .get_at(sym.st_name)
            .map(|name| name == "__stack_chk_fail" || name == "__stack_chk_guard")
            .unwrap_or(false)
    });

    // --- FORTIFY_SOURCE ---
    let fortify = elf.dynsyms.iter().any(|sym| {
        elf.dynstrtab
            .get_at(sym.st_name)
            .map(|name| name.ends_with("_chk") || name.contains("_chk@"))
            .unwrap_or(false)
    });

    // --- RPATH / RUNPATH ---
    let (rpath, runpath) = elf
        .dynamic
        .as_ref()
        .map(|d| {
            let has_rpath = d
                .dyns
                .iter()
                .any(|e| e.d_tag == goblin::elf::dynamic::DT_RPATH);
            let has_runpath = d
                .dyns
                .iter()
                .any(|e| e.d_tag == goblin::elf::dynamic::DT_RUNPATH);
            (has_rpath, has_runpath)
        })
        .unwrap_or((false, false));

    Ok(ChecksecResult {
        relro,
        canary,
        nx,
        pie,
        fortify,
        rpath,
        runpath,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_status_display() {
        assert_eq!(format!("{}", SecurityStatus::Full), "Full");
        assert_eq!(format!("{}", SecurityStatus::Partial), "Partial");
        assert_eq!(format!("{}", SecurityStatus::None), "None");
    }

    #[test]
    fn checksec_result_debug() {
        let result = ChecksecResult {
            relro: SecurityStatus::Full,
            canary: true,
            nx: true,
            pie: true,
            fortify: false,
            rpath: false,
            runpath: false,
        };
        // Just verify Debug impl works
        let _ = format!("{:?}", result);
    }
}
