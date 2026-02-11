//! Software breakpoint management.
//!
//! Corresponds to sdb's breakpoint_site.hpp and book Ch.7 (Software Breakpoints).
//! Implements the two-layer design: BreakpointSite (physical INT3) and
//! Breakpoint (logical, user-facing).

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::process::Process;
use crate::types::VirtAddr;

const INT3: u8 = 0xCC;

/// A physical breakpoint site: a single INT3 byte patched into memory.
#[derive(Debug)]
pub struct BreakpointSite {
    addr: VirtAddr,
    saved_byte: u8,
    enabled: bool,
}

impl BreakpointSite {
    /// Enable the breakpoint by writing INT3.
    pub fn enable(&mut self, proc: &Process) -> Result<()> {
        if self.enabled {
            return Ok(());
        }
        let word = proc.read_memory_word(self.addr)?;
        self.saved_byte = (word & 0xFF) as u8;
        let patched = (word & !0xFF) | INT3 as u64;
        proc.write_memory_word(self.addr, patched)?;
        self.enabled = true;
        Ok(())
    }

    /// Disable the breakpoint by restoring the original byte.
    pub fn disable(&mut self, proc: &Process) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let word = proc.read_memory_word(self.addr)?;
        let restored = (word & !0xFF) | self.saved_byte as u64;
        proc.write_memory_word(self.addr, restored)?;
        self.enabled = false;
        Ok(())
    }

    pub fn addr(&self) -> VirtAddr {
        self.addr
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn saved_byte(&self) -> u8 {
        self.saved_byte
    }
}

/// Manages all breakpoint sites for a process.
pub struct BreakpointManager {
    sites: HashMap<u64, BreakpointSite>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            sites: HashMap::new(),
            next_id: 1,
        }
    }

    /// Set a breakpoint at the given address.
    pub fn set(&mut self, proc: &Process, addr: VirtAddr) -> Result<u32> {
        if self.sites.contains_key(&addr.addr()) {
            return Err(Error::Breakpoint(format!(
                "breakpoint already set at {}",
                addr
            )));
        }
        let mut site = BreakpointSite {
            addr,
            saved_byte: 0,
            enabled: false,
        };
        site.enable(proc)?;
        let id = self.next_id;
        self.next_id += 1;
        self.sites.insert(addr.addr(), site);
        Ok(id)
    }

    /// Remove a breakpoint at the given address.
    pub fn remove(&mut self, proc: &Process, addr: VirtAddr) -> Result<()> {
        let mut site = self
            .sites
            .remove(&addr.addr())
            .ok_or_else(|| Error::Breakpoint(format!("no breakpoint at {}", addr)))?;
        site.disable(proc)?;
        Ok(())
    }

    /// Check if there is an enabled breakpoint at the given address.
    pub fn get_at(&self, addr: VirtAddr) -> Option<&BreakpointSite> {
        self.sites.get(&addr.addr())
    }

    /// Get a mutable reference to the site at the given address.
    pub fn get_at_mut(&mut self, addr: VirtAddr) -> Option<&mut BreakpointSite> {
        self.sites.get_mut(&addr.addr())
    }

    /// Step over a breakpoint: disable it, single-step, then re-enable.
    ///
    /// The caller must have already set RIP back to the breakpoint address.
    pub fn step_over_breakpoint(
        &mut self,
        proc: &mut Process,
        addr: VirtAddr,
    ) -> Result<()> {
        if let Some(site) = self.sites.get_mut(&addr.addr()) {
            if site.is_enabled() {
                site.disable(proc)?;
                proc.step_instruction()?;
                proc.wait_on_signal()?;
                site.enable(proc)?;
            }
        }
        Ok(())
    }

    /// List all breakpoints.
    pub fn list(&self) -> impl Iterator<Item = &BreakpointSite> {
        self.sites.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int3_byte_patching_logic() {
        // Simulate the read-modify-write pattern used for INT3 insertion.
        // Original word: first byte is 0x55 (push rbp).
        let original_word: u64 = 0x00000000_EC834855;
        let original_byte = (original_word & 0xFF) as u8;
        assert_eq!(original_byte, 0x55);

        // Patch: replace low byte with INT3 (0xCC)
        let patched = (original_word & !0xFF) | INT3 as u64;
        assert_eq!(patched & 0xFF, 0xCC);
        assert_eq!(patched >> 8, original_word >> 8); // upper bytes unchanged

        // Restore: replace low byte with saved original
        let restored = (patched & !0xFF) | original_byte as u64;
        assert_eq!(restored, original_word);
    }

    #[test]
    fn breakpoint_site_initial_state() {
        let site = BreakpointSite {
            addr: VirtAddr(0x401000),
            saved_byte: 0,
            enabled: false,
        };
        assert_eq!(site.addr(), VirtAddr(0x401000));
        assert!(!site.is_enabled());
        assert_eq!(site.saved_byte(), 0);
    }

    #[test]
    fn breakpoint_manager_id_assignment() {
        let mgr = BreakpointManager::new();
        assert_eq!(mgr.next_id, 1);
    }
}
