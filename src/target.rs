//! High-level debugger API.
//!
//! Corresponds to sdb's target.hpp/cpp.
//! Integrates process control, breakpoints, registers, ELF/DWARF info,
//! and source-level stepping into a unified interface used by the CLI.

use crate::breakpoint::BreakpointManager;
use crate::disasm::{self, DisasmInstruction, DisasmStyle};
use crate::dwarf::{DwarfInfo, SourceLocation};
use crate::elf::ElfFile;
use crate::error::Result;
use crate::process::Process;
use crate::procfs::{self, MemoryRegion};
use crate::registers::Registers;
use crate::types::{ProcessState, StopReason, VirtAddr};

use std::path::Path;

/// The main debugger session, owning the process and all debug state.
pub struct Target {
    process: Process,
    breakpoints: BreakpointManager,
    program_path: String,
    elf: ElfFile,
    dwarf: Option<DwarfInfo>,
}

impl Target {
    /// Launch a program and begin debugging it.
    pub fn launch(program: &Path, args: &[&str]) -> Result<Self> {
        let process = Process::launch(program, args)?;
        let elf = ElfFile::load(program)?;
        // DWARF info is optional: stripped binaries still work
        let dwarf = DwarfInfo::load(program).ok();
        Ok(Target {
            program_path: program.to_string_lossy().into_owned(),
            process,
            breakpoints: BreakpointManager::new(),
            elf,
            dwarf,
        })
    }

    /// Attach to an existing process by PID.
    pub fn attach(pid: nix::unistd::Pid) -> Result<Self> {
        let process = Process::attach(pid)?;
        let exe_path = format!("/proc/{}/exe", pid);
        let elf = ElfFile::load(Path::new(&exe_path))?;
        let dwarf = DwarfInfo::load(Path::new(&exe_path)).ok();
        Ok(Target {
            program_path: exe_path,
            process,
            breakpoints: BreakpointManager::new(),
            elf,
            dwarf,
        })
    }

    // ── Execution control ──────────────────────────────────────────

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

    /// Source-level step into: keep stepping until the source line changes.
    ///
    /// If no debug info is available, behaves like `step_instruction`.
    pub fn step_in(&mut self) -> Result<StopReason> {
        let start_loc = self.source_location()?;

        loop {
            let reason = self.step_instruction()?;
            match &reason {
                StopReason::SingleStep => {
                    let current_loc = self.source_location()?;
                    // If no debug info, return after a single step
                    if start_loc.is_none() || current_loc != start_loc {
                        return Ok(reason);
                    }
                    // Same line — keep stepping
                }
                _ => return Ok(reason),
            }
        }
    }

    /// Source-level step over: step one source line, skipping over calls.
    ///
    /// When the current instruction is a CALL, sets a temporary breakpoint
    /// at the return site and continues execution rather than stepping into
    /// the called function.
    pub fn step_over(&mut self) -> Result<StopReason> {
        let start_loc = self.source_location()?;

        loop {
            let pc = VirtAddr(self.read_registers()?.pc());
            let code = self.read_memory(pc, 15)?;

            if let Some(info) = disasm::decode_instruction_info(&code, pc) {
                if info.is_call {
                    let return_pc = VirtAddr(pc.addr() + info.len as u64);
                    let already_has_bp = self.breakpoints.get_at(return_pc).is_some();

                    if !already_has_bp {
                        self.set_breakpoint(return_pc)?;
                    }
                    let reason = self.resume()?;
                    if !already_has_bp {
                        let _ = self.remove_breakpoint(return_pc);
                    }

                    match &reason {
                        StopReason::BreakpointHit { addr } if *addr == return_pc => {
                            let current_loc = self.source_location()?;
                            if start_loc.is_none() || current_loc != start_loc {
                                return Ok(reason);
                            }
                            continue; // Same line, keep stepping
                        }
                        _ => return Ok(reason), // Stopped elsewhere
                    }
                }
            }

            // Not a CALL (or decode failed): single-step
            let reason = self.step_instruction()?;
            match &reason {
                StopReason::SingleStep => {
                    let current_loc = self.source_location()?;
                    if start_loc.is_none() || current_loc != start_loc {
                        return Ok(reason);
                    }
                }
                _ => return Ok(reason),
            }
        }
    }

    /// Step out: continue until the current function returns.
    ///
    /// Reads the return address from the stack frame (via frame pointer).
    /// Requires the binary to be compiled with frame pointers (`-fno-omit-frame-pointer`).
    pub fn step_out(&mut self) -> Result<StopReason> {
        let regs = self.read_registers()?;
        let rbp = regs.get("rbp")?;

        if rbp == 0 {
            return Err(crate::error::Error::Other(
                "cannot step out: no frame pointer (rbp=0)".into(),
            ));
        }

        // On x86_64 with frame pointers, return address is at [rbp + 8]
        let ret_addr_bytes = self.read_memory(VirtAddr(rbp + 8), 8)?;
        let ret_addr = u64::from_le_bytes(ret_addr_bytes[..8].try_into().unwrap());
        let ret_addr = VirtAddr(ret_addr);

        let already_has_bp = self.breakpoints.get_at(ret_addr).is_some();
        if !already_has_bp {
            self.set_breakpoint(ret_addr)?;
        }
        let reason = self.resume()?;
        if !already_has_bp {
            let _ = self.remove_breakpoint(ret_addr);
        }

        Ok(reason)
    }

    // ── Breakpoints ────────────────────────────────────────────────

    /// Set a breakpoint at an address.
    pub fn set_breakpoint(&mut self, addr: VirtAddr) -> Result<u32> {
        self.breakpoints.set(&self.process, addr)
    }

    /// Remove a breakpoint at an address.
    pub fn remove_breakpoint(&mut self, addr: VirtAddr) -> Result<()> {
        self.breakpoints.remove(&self.process, addr)
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<VirtAddr> {
        self.breakpoints.list().map(|s| s.addr()).collect()
    }

    // ── Registers ──────────────────────────────────────────────────

    /// Read all registers.
    pub fn read_registers(&self) -> Result<Registers> {
        Registers::read(self.process.pid())
    }

    /// Write registers back to the tracee.
    pub fn write_registers(&self, regs: &Registers) -> Result<()> {
        regs.write(self.process.pid())
    }

    // ── Memory ─────────────────────────────────────────────────────

    /// Read memory from the tracee.
    pub fn read_memory(&self, addr: VirtAddr, len: usize) -> Result<Vec<u8>> {
        self.process.read_memory(addr, len)
    }

    /// Read the tracee's memory maps from `/proc/pid/maps`.
    pub fn memory_maps(&self) -> Result<Vec<MemoryRegion>> {
        procfs::read_memory_maps(self.process.pid())
    }

    // ── Disassembly ────────────────────────────────────────────────

    /// Disassemble instructions at the given address.
    pub fn disassemble(
        &self,
        addr: VirtAddr,
        count: usize,
        style: DisasmStyle,
    ) -> Result<Vec<DisasmInstruction>> {
        let read_len = count * 15;
        let code = self.process.read_memory(addr, read_len)?;
        Ok(disasm::disassemble(&code, addr, count, style))
    }

    /// Disassemble at the current instruction pointer.
    pub fn disassemble_at_pc(
        &self,
        count: usize,
        style: DisasmStyle,
    ) -> Result<Vec<DisasmInstruction>> {
        let regs = self.read_registers()?;
        let pc = VirtAddr(regs.pc());
        self.disassemble(pc, count, style)
    }

    // ── Source info ────────────────────────────────────────────────

    /// Get the source location at the current PC.
    pub fn source_location(&self) -> Result<Option<SourceLocation>> {
        let pc = VirtAddr(self.read_registers()?.pc());
        match &self.dwarf {
            Some(dwarf) => dwarf.find_location(pc),
            None => Ok(None),
        }
    }

    /// Get the function name at the current PC.
    ///
    /// Tries the ELF symbol table first, then falls back to DWARF info.
    pub fn current_function(&self) -> Result<Option<String>> {
        let pc = VirtAddr(self.read_registers()?.pc());
        // ELF symbols (works even without debug info)
        if let Some(sym) = self.elf.find_symbol_at(pc) {
            return Ok(Some(sym.name.clone()));
        }
        // DWARF function info (handles inlined functions)
        if let Some(dwarf) = &self.dwarf {
            return dwarf.find_function(pc);
        }
        Ok(None)
    }

    /// Find an ELF symbol by name and return its address.
    pub fn find_symbol(&self, name: &str) -> Option<VirtAddr> {
        self.elf.find_symbol(name).map(|s| s.addr)
    }

    /// Check whether DWARF debug info is available.
    pub fn has_debug_info(&self) -> bool {
        self.dwarf.is_some()
    }

    // ── Accessors ──────────────────────────────────────────────────

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

    /// Get the ELF file reference.
    pub fn elf(&self) -> &ElfFile {
        &self.elf
    }

    // ── Internal ───────────────────────────────────────────────────

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
