//! High-level debugger API.
//!
//! Corresponds to sdb's target.hpp/cpp.
//! Integrates process control, breakpoints, and registers into a
//! unified interface used by the CLI.

use crate::breakpoint::BreakpointManager;
use crate::error::Result;
use crate::process::Process;
use crate::registers::Registers;
use crate::types::{ProcessState, StopReason, VirtAddr};

use std::path::Path;

/// The main debugger session, owning the process and all debug state.
pub struct Target {
    process: Process,
    breakpoints: BreakpointManager,
    program_path: String,
}

impl Target {
    /// Launch a program and begin debugging it.
    pub fn launch(program: &Path, args: &[&str]) -> Result<Self> {
        let process = Process::launch(program, args)?;
        Ok(Target {
            program_path: program.to_string_lossy().into_owned(),
            process,
            breakpoints: BreakpointManager::new(),
        })
    }

    /// Attach to an existing process by PID.
    pub fn attach(pid: nix::unistd::Pid) -> Result<Self> {
        let process = Process::attach(pid)?;
        Ok(Target {
            program_path: format!("/proc/{}/exe", pid),
            process,
            breakpoints: BreakpointManager::new(),
        })
    }

    /// Continue execution until the next stop event.
    pub fn resume(&mut self) -> Result<StopReason> {
        self.process.resume()?;
        let reason = self.process.wait_on_signal()?;
        self.handle_stop(&reason)?;
        Ok(reason)
    }

    /// Execute a single machine instruction.
    pub fn step_instruction(&mut self) -> Result<StopReason> {
        // If we're sitting on a breakpoint, step over it first
        let pc = VirtAddr(self.read_registers()?.pc());
        if self.breakpoints.get_at(pc).is_some() {
            self.breakpoints.step_over_breakpoint(&mut self.process, pc)?;
            return Ok(StopReason::SingleStep);
        }

        self.process.step_instruction()?;
        let reason = self.process.wait_on_signal()?;
        self.handle_stop(&reason)?;
        Ok(reason)
    }

    /// Set a breakpoint at an address.
    pub fn set_breakpoint(&mut self, addr: VirtAddr) -> Result<u32> {
        self.breakpoints.set(&self.process, addr)
    }

    /// Remove a breakpoint at an address.
    pub fn remove_breakpoint(&mut self, addr: VirtAddr) -> Result<()> {
        self.breakpoints.remove(&self.process, addr)
    }

    /// Read all registers.
    pub fn read_registers(&self) -> Result<Registers> {
        Registers::read(self.process.pid())
    }

    /// Write registers back to the tracee.
    pub fn write_registers(&self, regs: &Registers) -> Result<()> {
        regs.write(self.process.pid())
    }

    /// Read memory from the tracee.
    pub fn read_memory(&self, addr: VirtAddr, len: usize) -> Result<Vec<u8>> {
        self.process.read_memory(addr, len)
    }

    /// Get the process state.
    pub fn state(&self) -> ProcessState {
        self.process.state()
    }

    /// Get the PID.
    pub fn pid(&self) -> nix::unistd::Pid {
        self.process.pid()
    }

    /// Get the program path.
    pub fn program_path(&self) -> &str {
        &self.program_path
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<VirtAddr> {
        self.breakpoints.list().map(|s| s.addr()).collect()
    }

    /// Handle a stop event (e.g., adjust PC after breakpoint hit).
    fn handle_stop(&mut self, reason: &StopReason) -> Result<()> {
        if let StopReason::BreakpointHit { addr } = reason {
            // Set RIP back to the breakpoint address (INT3 advanced it by 1)
            let mut regs = self.read_registers()?;
            regs.set_pc(addr.addr());
            self.write_registers(&regs)?;
        }
        Ok(())
    }
}
