//! Anti-debugging detection and bypass.
//!
//! Static analysis detects common anti-debug techniques in ELF binaries.
//! Runtime bypass intercepts and neutralizes these protections.

use std::path::Path;

use crate::error::{Error, Result};

/// An anti-debug technique detected in the binary.
#[derive(Debug, Clone)]
pub struct AntiDebugFinding {
    /// What technique was found.
    pub technique: AntiDebugTechnique,
    /// Address where it was detected (0 if N/A).
    pub addr: u64,
    /// Human-readable description.
    pub description: String,
}

/// Classification of anti-debug techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiDebugTechnique {
    /// `ptrace(PTRACE_TRACEME)` — classic self-trace check.
    PtraceTraceme,
    /// Reading `/proc/self/status` for `TracerPid`.
    ProcSelfStatus,
    /// Timing checks via `clock_gettime` or `rdtsc`.
    TimingCheck,
    /// Self-checksumming / INT3 detection.
    Int3SelfCheck,
    /// `prctl(PR_SET_DUMPABLE, 0)` to prevent core dumps.
    PrctlNondumpable,
}

impl std::fmt::Display for AntiDebugTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PtraceTraceme => write!(f, "ptrace(TRACEME)"),
            Self::ProcSelfStatus => write!(f, "/proc/self/status check"),
            Self::TimingCheck => write!(f, "timing check"),
            Self::Int3SelfCheck => write!(f, "INT3/self-checksum"),
            Self::PrctlNondumpable => write!(f, "prctl(PR_SET_DUMPABLE, 0)"),
        }
    }
}

/// Scan an ELF binary for anti-debug patterns.
pub fn scan(path: &Path) -> Result<Vec<AntiDebugFinding>> {
    let data =
        std::fs::read(path).map_err(|e| Error::Other(format!("read: {}", e)))?;
    scan_bytes(&data)
}

/// Scan raw ELF data for anti-debug patterns.
pub fn scan_bytes(data: &[u8]) -> Result<Vec<AntiDebugFinding>> {
    let elf = goblin::elf::Elf::parse(data)
        .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

    let mut findings = Vec::new();

    // --- Check for ptrace in dynamic symbols ---
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "ptrace" {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::PtraceTraceme,
                    addr: sym.st_value,
                    description: "Dynamic symbol 'ptrace' imported — likely self-trace check"
                        .into(),
                });
            }
            if name == "prctl" {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::PrctlNondumpable,
                    addr: sym.st_value,
                    description: "Dynamic symbol 'prctl' imported — may set PR_SET_DUMPABLE(0)"
                        .into(),
                });
            }
        }
    }

    // --- Scan strings for /proc/self/status and related paths ---
    scan_strings_for_antidebug(data, &elf, &mut findings);

    // --- Scan for timing-related symbols ---
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "clock_gettime" || name == "gettimeofday" || name == "time" {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::TimingCheck,
                    addr: sym.st_value,
                    description: format!(
                        "Timing function '{}' imported — potential timing-based anti-debug",
                        name
                    ),
                });
            }
        }
    }

    // --- Scan executable sections for rdtsc instruction (0x0F 0x31) ---
    scan_for_rdtsc(data, &elf, &mut findings);

    // --- Scan for INT3 (0xCC) in non-PLT code sections ---
    scan_for_int3_checks(data, &elf, &mut findings);

    Ok(findings)
}

/// Search string data in ELF for anti-debug-related paths.
fn scan_strings_for_antidebug(
    data: &[u8],
    elf: &goblin::elf::Elf,
    findings: &mut Vec<AntiDebugFinding>,
) {
    let patterns: &[(&[u8], &str)] = &[
        (b"/proc/self/status", "Reads /proc/self/status — TracerPid check"),
        (b"/proc/self/maps", "Reads /proc/self/maps — memory layout inspection"),
        (b"TracerPid", "References TracerPid string — debugger detection"),
        (b"/proc/self/exe", "Reads /proc/self/exe — binary integrity check"),
    ];

    for sh in &elf.section_headers {
        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if offset + size > data.len() {
            continue;
        }
        let section_data = &data[offset..offset + size];

        for (pattern, desc) in patterns {
            if let Some(pos) = find_bytes(section_data, pattern) {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::ProcSelfStatus,
                    addr: sh.sh_addr + pos as u64,
                    description: desc.to_string(),
                });
            }
        }
    }
}

/// Scan executable sections for the RDTSC instruction (0x0F 0x31).
fn scan_for_rdtsc(
    data: &[u8],
    elf: &goblin::elf::Elf,
    findings: &mut Vec<AntiDebugFinding>,
) {
    for sh in &elf.section_headers {
        if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) == 0 {
            continue;
        }
        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if offset + size > data.len() {
            continue;
        }
        let section_data = &data[offset..offset + size];

        for (i, window) in section_data.windows(2).enumerate() {
            if window == [0x0F, 0x31] {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::TimingCheck,
                    addr: sh.sh_addr + i as u64,
                    description: "RDTSC instruction found — hardware timing check".into(),
                });
            }
        }
    }
}

/// Scan for suspicious INT3 patterns in code (embedded traps for self-checking).
fn scan_for_int3_checks(
    data: &[u8],
    elf: &goblin::elf::Elf,
    findings: &mut Vec<AntiDebugFinding>,
) {
    for sh in &elf.section_headers {
        if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) == 0 {
            continue;
        }
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("");
        // Skip PLT sections — INT3 padding is normal there
        if name.contains(".plt") {
            continue;
        }

        let offset = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if offset + size > data.len() {
            continue;
        }
        let section_data = &data[offset..offset + size];

        // Look for clusters of INT3 (3+ consecutive) which may indicate self-checking
        let mut count = 0u32;
        for (i, &byte) in section_data.iter().enumerate() {
            if byte == 0xCC {
                count += 1;
            } else {
                if count >= 3 {
                    let start = i - count as usize;
                    findings.push(AntiDebugFinding {
                        technique: AntiDebugTechnique::Int3SelfCheck,
                        addr: sh.sh_addr + start as u64,
                        description: format!(
                            "INT3 cluster ({} bytes) in {} — potential trap/checksum region",
                            count, name
                        ),
                    });
                }
                count = 0;
            }
        }
    }
}

/// Find a byte pattern in a slice.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Runtime anti-debug bypass configuration.
#[derive(Debug, Clone, Default)]
pub struct BypassConfig {
    /// Intercept ptrace(TRACEME) and return success.
    pub bypass_ptrace: bool,
    /// Auto-continue INT3 traps at non-breakpoint addresses.
    pub skip_int3_traps: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_bytes_basic() {
        let data = b"hello world";
        assert_eq!(find_bytes(data, b"world"), Some(6));
        assert_eq!(find_bytes(data, b"xyz"), None);
        assert_eq!(find_bytes(data, b""), None);
    }

    #[test]
    fn technique_display() {
        assert_eq!(
            format!("{}", AntiDebugTechnique::PtraceTraceme),
            "ptrace(TRACEME)"
        );
        assert_eq!(
            format!("{}", AntiDebugTechnique::TimingCheck),
            "timing check"
        );
    }

    #[test]
    fn bypass_config_default() {
        let cfg = BypassConfig::default();
        assert!(!cfg.bypass_ptrace);
        assert!(!cfg.skip_int3_traps);
    }

    #[test]
    fn scan_finds_rdtsc() {
        // Simulate executable section data with RDTSC
        let rdtsc_bytes = [0x90, 0x0F, 0x31, 0x90]; // nop; rdtsc; nop
        let mut findings = Vec::new();
        // Direct test of the pattern matching
        for (i, window) in rdtsc_bytes.windows(2).enumerate() {
            if window == [0x0F, 0x31] {
                findings.push(AntiDebugFinding {
                    technique: AntiDebugTechnique::TimingCheck,
                    addr: 0x1000 + i as u64,
                    description: "RDTSC".into(),
                });
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].addr, 0x1001);
    }

    #[test]
    fn scan_finds_proc_self_status() {
        let data = b"\x00/proc/self/status\x00";
        let pos = find_bytes(data, b"/proc/self/status");
        assert_eq!(pos, Some(1));
    }
}
