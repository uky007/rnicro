//! Hardware watchpoint management via x86_64 debug registers.
//!
//! Corresponds to sdb's watchpoint.hpp/cpp and book Ch.12.
//!
//! Uses DR0–DR3 for addresses, DR6 for status, and DR7 for control.
//! Each of the four slots can monitor 1/2/4/8 bytes for write or
//! read-write access at an aligned address.

use crate::error::{Error, Result};
use crate::process;
use crate::types::VirtAddr;

use nix::unistd::Pid;

/// What kind of access to trap on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchpointType {
    /// Trap on writes only (DR7 condition = 0b01).
    Write,
    /// Trap on reads or writes (DR7 condition = 0b11).
    ReadWrite,
    /// Trap on execution (DR7 condition = 0b00).
    Execute,
}

impl WatchpointType {
    /// DR7 condition field encoding.
    fn dr7_condition(self) -> u64 {
        match self {
            WatchpointType::Write => 0b01,
            WatchpointType::ReadWrite => 0b11,
            WatchpointType::Execute => 0b00,
        }
    }
}

impl std::fmt::Display for WatchpointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchpointType::Write => write!(f, "write"),
            WatchpointType::ReadWrite => write!(f, "rw"),
            WatchpointType::Execute => write!(f, "execute"),
        }
    }
}

/// Size of the watched region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchpointSize {
    /// 1 byte (DR7 length = 0b00).
    Byte1,
    /// 2 bytes (DR7 length = 0b01).
    Byte2,
    /// 4 bytes (DR7 length = 0b11).
    Byte4,
    /// 8 bytes (DR7 length = 0b10).
    Byte8,
}

impl WatchpointSize {
    /// DR7 length field encoding.
    fn dr7_length(self) -> u64 {
        match self {
            WatchpointSize::Byte1 => 0b00,
            WatchpointSize::Byte2 => 0b01,
            WatchpointSize::Byte4 => 0b11,
            WatchpointSize::Byte8 => 0b10,
        }
    }

    /// Size in bytes.
    pub fn bytes(self) -> usize {
        match self {
            WatchpointSize::Byte1 => 1,
            WatchpointSize::Byte2 => 2,
            WatchpointSize::Byte4 => 4,
            WatchpointSize::Byte8 => 8,
        }
    }

    /// Parse from byte count.
    pub fn from_bytes(n: usize) -> Option<Self> {
        match n {
            1 => Some(WatchpointSize::Byte1),
            2 => Some(WatchpointSize::Byte2),
            4 => Some(WatchpointSize::Byte4),
            8 => Some(WatchpointSize::Byte8),
            _ => None,
        }
    }
}

impl std::fmt::Display for WatchpointSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bytes())
    }
}

/// A single hardware watchpoint stored in a debug register slot.
#[derive(Debug, Clone)]
pub struct Watchpoint {
    /// Unique ID (auto-incrementing).
    pub id: u32,
    /// Watched address.
    pub addr: VirtAddr,
    /// Access type.
    pub wp_type: WatchpointType,
    /// Watched region size.
    pub size: WatchpointSize,
    /// Hardware slot (0–3, corresponding to DR0–DR3).
    pub slot: usize,
}

/// Manages up to 4 hardware watchpoints using x86_64 debug registers.
pub struct WatchpointManager {
    /// Active watchpoints indexed by slot (None = free).
    slots: [Option<Watchpoint>; 4],
    /// Next watchpoint ID.
    next_id: u32,
}

impl WatchpointManager {
    pub fn new() -> Self {
        WatchpointManager {
            slots: [None, None, None, None],
            next_id: 1,
        }
    }

    /// Set a hardware watchpoint. Returns the watchpoint ID.
    ///
    /// Finds a free debug register slot, writes the address to DR0–DR3,
    /// and configures DR7 with the enable bit, condition, and length.
    pub fn set(
        &mut self,
        pid: Pid,
        addr: VirtAddr,
        wp_type: WatchpointType,
        size: WatchpointSize,
    ) -> Result<u32> {
        // Alignment check: address must be aligned to size
        let align = size.bytes() as u64;
        if addr.addr() & (align - 1) != 0 {
            return Err(Error::Other(format!(
                "watchpoint address {:#x} must be aligned to {} bytes",
                addr.addr(),
                align
            )));
        }

        // Find a free slot
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or_else(|| {
                Error::Other("no free hardware debug registers (max 4 watchpoints)".into())
            })?;

        // Write address to DR<slot>
        process::write_debug_reg(pid, slot, addr.addr())?;

        // Read current DR7, set enable + condition + length for this slot
        let mut dr7 = process::read_debug_reg(pid, 7)?;

        // Clear any existing bits for this slot
        let enable_mask = 0b11u64 << (slot * 2);
        let config_mask = 0b1111u64 << (slot * 4 + 16);
        dr7 &= !(enable_mask | config_mask);

        // Set local enable bit
        dr7 |= 1u64 << (slot * 2);
        // Set condition (R/W) bits
        dr7 |= wp_type.dr7_condition() << (slot * 4 + 16);
        // Set length bits
        dr7 |= size.dr7_length() << (slot * 4 + 18);

        process::write_debug_reg(pid, 7, dr7)?;

        let id = self.next_id;
        self.next_id += 1;
        self.slots[slot] = Some(Watchpoint {
            id,
            addr,
            wp_type,
            size,
            slot,
        });

        Ok(id)
    }

    /// Remove a watchpoint by ID.
    pub fn remove(&mut self, pid: Pid, id: u32) -> Result<()> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.as_ref().map(|w| w.id) == Some(id))
            .ok_or_else(|| Error::Other(format!("no watchpoint with id {}", id)))?;

        self.clear_slot(pid, slot)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// Remove a watchpoint by address.
    pub fn remove_at(&mut self, pid: Pid, addr: VirtAddr) -> Result<()> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.as_ref().map(|w| w.addr) == Some(addr))
            .ok_or_else(|| Error::Other(format!("no watchpoint at {}", addr)))?;

        self.clear_slot(pid, slot)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// Check which watchpoint was hit by reading DR6.
    ///
    /// Returns the slot index and address if a watchpoint triggered.
    /// Clears DR6 after reading.
    pub fn get_hit(&self, pid: Pid) -> Result<Option<(usize, VirtAddr)>> {
        let dr6 = process::read_debug_reg(pid, 6)?;

        for i in 0..4 {
            if dr6 & (1 << i) != 0 {
                if let Some(wp) = &self.slots[i] {
                    // Clear DR6 status
                    process::write_debug_reg(pid, 6, 0)?;
                    return Ok(Some((i, wp.addr)));
                }
            }
        }

        // Clear DR6 even if no match found
        process::write_debug_reg(pid, 6, 0)?;
        Ok(None)
    }

    /// List all active watchpoints.
    pub fn list(&self) -> Vec<&Watchpoint> {
        self.slots.iter().filter_map(|s| s.as_ref()).collect()
    }

    /// Get a watchpoint by slot.
    pub fn get_at_slot(&self, slot: usize) -> Option<&Watchpoint> {
        self.slots.get(slot).and_then(|s| s.as_ref())
    }

    /// Clear a debug register slot: zero the address and disable bits in DR7.
    fn clear_slot(&self, pid: Pid, slot: usize) -> Result<()> {
        // Zero the address register
        process::write_debug_reg(pid, slot, 0)?;

        // Clear enable + condition + length bits in DR7
        let mut dr7 = process::read_debug_reg(pid, 7)?;
        let enable_mask = 0b11u64 << (slot * 2);
        let config_mask = 0b1111u64 << (slot * 4 + 16);
        dr7 &= !(enable_mask | config_mask);
        process::write_debug_reg(pid, 7, dr7)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchpoint_type_dr7_condition() {
        assert_eq!(WatchpointType::Write.dr7_condition(), 0b01);
        assert_eq!(WatchpointType::ReadWrite.dr7_condition(), 0b11);
        assert_eq!(WatchpointType::Execute.dr7_condition(), 0b00);
    }

    #[test]
    fn watchpoint_size_dr7_length() {
        assert_eq!(WatchpointSize::Byte1.dr7_length(), 0b00);
        assert_eq!(WatchpointSize::Byte2.dr7_length(), 0b01);
        assert_eq!(WatchpointSize::Byte4.dr7_length(), 0b11);
        assert_eq!(WatchpointSize::Byte8.dr7_length(), 0b10);
    }

    #[test]
    fn watchpoint_size_conversion() {
        assert_eq!(WatchpointSize::from_bytes(1), Some(WatchpointSize::Byte1));
        assert_eq!(WatchpointSize::from_bytes(2), Some(WatchpointSize::Byte2));
        assert_eq!(WatchpointSize::from_bytes(4), Some(WatchpointSize::Byte4));
        assert_eq!(WatchpointSize::from_bytes(8), Some(WatchpointSize::Byte8));
        assert_eq!(WatchpointSize::from_bytes(3), None);
        assert_eq!(WatchpointSize::from_bytes(16), None);
    }

    #[test]
    fn watchpoint_type_display() {
        assert_eq!(format!("{}", WatchpointType::Write), "write");
        assert_eq!(format!("{}", WatchpointType::ReadWrite), "rw");
        assert_eq!(format!("{}", WatchpointType::Execute), "execute");
    }

    #[test]
    fn watchpoint_manager_empty() {
        let mgr = WatchpointManager::new();
        assert!(mgr.list().is_empty());
        assert!(mgr.get_at_slot(0).is_none());
        assert!(mgr.get_at_slot(4).is_none());
    }
}
