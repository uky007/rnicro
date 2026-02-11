//! Stack unwinding via DWARF Call Frame Information (CFI).
//!
//! Corresponds to sdb's stack unwinding and book Ch.10.
//! Parses `.eh_frame` section to walk the call stack, enabling
//! backtrace display and CFI-based `step_out`.

use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use gimli::{BaseAddresses, CfaRule, EhFrame, EndianRcSlice, Register, RegisterRule,
            RunTimeEndian, UnwindContext, UnwindSection};
use object::{Object, ObjectSection};

use crate::error::{Error, Result};
use crate::types::VirtAddr;

type GimliReader = EndianRcSlice<RunTimeEndian>;

/// A single frame from stack unwinding.
#[derive(Debug, Clone)]
pub struct UnwindFrame {
    /// Instruction pointer for this frame.
    pub pc: VirtAddr,
    /// Canonical Frame Address (stack pointer at the call site).
    pub cfa: u64,
}

/// Stack unwinder using DWARF `.eh_frame` CFI data.
pub struct Unwinder {
    eh_frame: EhFrame<GimliReader>,
    bases: BaseAddresses,
}

impl Unwinder {
    /// Load `.eh_frame` from an ELF binary.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Other(format!("read ELF for unwind: {}", e)))?;
        let obj = object::File::parse(&*data)
            .map_err(|e| Error::Other(format!("parse ELF for unwind: {}", e)))?;

        let eh_frame_data = obj
            .section_by_name(".eh_frame")
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);

        let eh_frame_addr = obj
            .section_by_name(".eh_frame")
            .map(|s| s.address())
            .unwrap_or(0);

        let text_addr = obj
            .section_by_name(".text")
            .map(|s| s.address())
            .unwrap_or(0);

        let reader = EndianRcSlice::new(Rc::from(eh_frame_data), RunTimeEndian::Little);
        let mut eh_frame = EhFrame::from(reader);
        eh_frame.set_address_size(8); // x86_64

        let bases = BaseAddresses::default()
            .set_eh_frame(eh_frame_addr)
            .set_text(text_addr);

        Ok(Unwinder { eh_frame, bases })
    }

    /// Walk the call stack from the given register state.
    ///
    /// # Arguments
    /// * `initial_pc` - Current instruction pointer.
    /// * `initial_regs` - DWARF register number → value pairs.
    /// * `read_memory` - Closure to read tracee memory.
    ///
    /// Returns frames from innermost (current) to outermost (main/_start).
    pub fn walk_stack(
        &self,
        initial_pc: u64,
        initial_regs: &[(u16, u64)],
        read_memory: &dyn Fn(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Vec<UnwindFrame>> {
        let mut frames = Vec::new();
        let mut pc = initial_pc;
        let mut regs: HashMap<Register, u64> =
            initial_regs.iter().map(|&(r, v)| (Register(r), v)).collect();
        let mut ctx = UnwindContext::new();

        for depth in 0..256 {
            let cfa_val = regs.get(&Register(7)).copied().unwrap_or(0); // RSP
            frames.push(UnwindFrame {
                pc: VirtAddr(pc),
                cfa: cfa_val,
            });

            // For frames after the first, subtract 1 from PC to handle
            // the case where PC points to the instruction after a CALL.
            let lookup_pc = if depth == 0 { pc } else { pc.saturating_sub(1) };

            // Find the FDE covering this address
            let fde = match self.eh_frame.fde_for_address(
                &self.bases,
                lookup_pc,
                |section, bases, offset| section.cie_from_offset(bases, offset),
            ) {
                Ok(fde) => fde,
                Err(_) => break,
            };

            let row = match fde.unwind_info_for_address(
                &self.eh_frame,
                &self.bases,
                &mut ctx,
                lookup_pc,
            ) {
                Ok(row) => row,
                Err(_) => break,
            };

            // Compute CFA (Canonical Frame Address)
            let cfa = match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => {
                    let reg_val = regs.get(register).copied().unwrap_or(0);
                    (reg_val as i64 + *offset) as u64
                }
                CfaRule::Expression(_) => break, // Expression evaluation not yet supported
            };

            // Update the frame's CFA with the computed value
            if let Some(frame) = frames.last_mut() {
                frame.cfa = cfa;
            }

            // Read return address from the stack
            let ra_register = fde.cie().return_address_register();
            let new_pc = match row.register(ra_register) {
                RegisterRule::Offset(offset) => {
                    let addr = (cfa as i64 + offset) as u64;
                    let bytes = read_memory(addr, 8)?;
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
                }
                RegisterRule::Register(reg) => regs.get(&reg).copied().unwrap_or(0),
                RegisterRule::Undefined => break,
                _ => break,
            };

            if new_pc == 0 {
                break;
            }

            // Restore callee-saved registers for the next frame
            let mut new_regs = HashMap::new();
            new_regs.insert(Register(7), cfa); // RSP = CFA

            for (&reg, &val) in &regs {
                match row.register(reg) {
                    RegisterRule::SameValue => {
                        new_regs.insert(reg, val);
                    }
                    RegisterRule::Offset(offset) => {
                        let addr = (cfa as i64 + offset) as u64;
                        if let Ok(bytes) = read_memory(addr, 8) {
                            new_regs.insert(
                                reg,
                                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                            );
                        }
                    }
                    RegisterRule::Register(other) => {
                        if let Some(&v) = regs.get(&other) {
                            new_regs.insert(reg, v);
                        }
                    }
                    RegisterRule::ValOffset(offset) => {
                        new_regs.insert(reg, (cfa as i64 + offset) as u64);
                    }
                    _ => {} // Undefined, expression, etc.
                }
            }

            pc = new_pc;
            regs = new_regs;
        }

        Ok(frames)
    }

    /// Get just the return address for the current frame.
    ///
    /// Used by `step_out` to find where to set the temporary breakpoint.
    /// Falls back to `None` if CFI data doesn't cover the current PC.
    pub fn return_address(
        &self,
        pc: u64,
        initial_regs: &[(u16, u64)],
        read_memory: &dyn Fn(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Option<u64>> {
        let regs: HashMap<Register, u64> =
            initial_regs.iter().map(|&(r, v)| (Register(r), v)).collect();
        let mut ctx = UnwindContext::new();

        let fde = match self.eh_frame.fde_for_address(
            &self.bases,
            pc,
            |section, bases, offset| section.cie_from_offset(bases, offset),
        ) {
            Ok(fde) => fde,
            Err(_) => return Ok(None),
        };

        let row = match fde.unwind_info_for_address(
            &self.eh_frame,
            &self.bases,
            &mut ctx,
            pc,
        ) {
            Ok(row) => row,
            Err(_) => return Ok(None),
        };

        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                let reg_val = regs.get(register).copied().unwrap_or(0);
                (reg_val as i64 + *offset) as u64
            }
            _ => return Ok(None),
        };

        let ra_register = fde.cie().return_address_register();
        match row.register(ra_register) {
            RegisterRule::Offset(offset) => {
                let addr = (cfa as i64 + offset) as u64;
                let bytes = read_memory(addr, 8)?;
                Ok(Some(u64::from_le_bytes(bytes[..8].try_into().unwrap())))
            }
            RegisterRule::Register(reg) => Ok(regs.get(&reg).copied()),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwind_frame_creation() {
        let frame = UnwindFrame {
            pc: VirtAddr(0x401000),
            cfa: 0x7fffffffde00,
        };
        assert_eq!(frame.pc, VirtAddr(0x401000));
        assert_eq!(frame.cfa, 0x7fffffffde00);
    }

    #[test]
    fn empty_walk_returns_at_least_one_frame() {
        // When no .eh_frame data is available, walk_stack should still
        // return the initial frame.
        let reader = EndianRcSlice::new(Rc::from(&[] as &[u8]), RunTimeEndian::Little);
        let mut eh_frame = EhFrame::from(reader);
        eh_frame.set_address_size(8);
        let bases = BaseAddresses::default();

        let unwinder = Unwinder { eh_frame, bases };
        let regs = vec![(7u16, 0x7fffffffde00u64), (16, 0x401000)]; // RSP, RIP
        let frames = unwinder
            .walk_stack(0x401000, &regs, &|_, _| Ok(vec![0; 8]))
            .unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].pc, VirtAddr(0x401000));
    }
}
