//! High-level debugger API.
//!
//! Corresponds to sdb's target.hpp/cpp.
//! Integrates process control, breakpoints, registers, ELF/DWARF info,
//! stack unwinding, and source-level stepping into a unified interface
//! used by the CLI.

use crate::breakpoint::BreakpointManager;
use crate::disasm::{self, DisasmInstruction, DisasmStyle};
use crate::dwarf::{DwarfInfo, SourceLocation};
use crate::elf::ElfFile;
use crate::error::{Error, Result};
use crate::process::Process;
use crate::procfs::{self, MemoryRegion};
use crate::registers::{self, Registers};
use crate::types::{ProcessState, StopReason, VirtAddr};
use crate::unwind::Unwinder;
use crate::watchpoint::{WatchpointManager, WatchpointType, WatchpointSize, Watchpoint};

use nix::sys::signal::Signal;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Per-signal handling policy.
#[derive(Debug, Clone, Copy)]
pub struct SignalPolicy {
    /// Stop execution when this signal is received.
    pub stop: bool,
    /// Pass (deliver) the signal to the tracee on resume.
    pub pass: bool,
}

impl Default for SignalPolicy {
    fn default() -> Self {
        SignalPolicy {
            stop: true,
            pass: false,
        }
    }
}

/// A frame in the backtrace, enriched with symbol and source info.
#[derive(Debug)]
pub struct BacktraceFrame {
    /// Frame number (0 = innermost).
    pub index: usize,
    /// Instruction pointer for this frame.
    pub pc: VirtAddr,
    /// Function name (from ELF symbols or DWARF).
    pub function: Option<String>,
    /// Source location (from DWARF line tables).
    pub location: Option<SourceLocation>,
}

/// The main debugger session, owning the process and all debug state.
pub struct Target {
    process: Process,
    breakpoints: BreakpointManager,
    watchpoints: WatchpointManager,
    program_path: String,
    elf: ElfFile,
    dwarf: Option<DwarfInfo>,
    unwinder: Option<Unwinder>,
    /// Per-signal handling policy.
    signal_policies: HashMap<Signal, SignalPolicy>,
    /// Signal to deliver on the next resume (set when policy says "pass").
    pending_signal: Option<Signal>,
    /// Set of syscall numbers being caught (empty = not catching).
    caught_syscalls: HashSet<u64>,
    /// Whether to catch all syscalls.
    catch_all_syscalls: bool,
}

impl Target {
    /// Launch a program and begin debugging it.
    pub fn launch(program: &Path, args: &[&str]) -> Result<Self> {
        let process = Process::launch(program, args)?;
        let elf = ElfFile::load(program)?;
        let dwarf = DwarfInfo::load(program).ok();
        let unwinder = Unwinder::load(program).ok();
        Ok(Target {
            program_path: program.to_string_lossy().into_owned(),
            process,
            breakpoints: BreakpointManager::new(),
            watchpoints: WatchpointManager::new(),
            elf,
            dwarf,
            unwinder,
            signal_policies: HashMap::new(),
            pending_signal: None,
            caught_syscalls: HashSet::new(),
            catch_all_syscalls: false,
        })
    }

    /// Attach to an existing process by PID.
    pub fn attach(pid: nix::unistd::Pid) -> Result<Self> {
        let process = Process::attach(pid)?;
        let exe_path = format!("/proc/{}/exe", pid);
        let elf = ElfFile::load(Path::new(&exe_path))?;
        let dwarf = DwarfInfo::load(Path::new(&exe_path)).ok();
        let unwinder = Unwinder::load(Path::new(&exe_path)).ok();
        Ok(Target {
            program_path: exe_path,
            process,
            breakpoints: BreakpointManager::new(),
            watchpoints: WatchpointManager::new(),
            elf,
            dwarf,
            unwinder,
            signal_policies: HashMap::new(),
            pending_signal: None,
            caught_syscalls: HashSet::new(),
            catch_all_syscalls: false,
        })
    }

    // ── Execution control ──────────────────────────────────────────

    /// Continue execution until the next stop event.
    ///
    /// Delivers a pending signal if one was stored by the signal policy.
    /// Uses PTRACE_SYSCALL instead of PTRACE_CONT when syscall catching is active.
    pub fn resume(&mut self) -> Result<StopReason> {
        loop {
            let sig = self.pending_signal.take();
            if self.catch_all_syscalls || !self.caught_syscalls.is_empty() {
                self.process.resume_with_syscall_trap(sig)?;
            } else if let Some(s) = sig {
                self.process.resume_with_signal(s)?;
            } else {
                self.process.resume()?;
            }
            let reason = self.process.wait_on_signal()?;
            self.handle_stop(&reason)?;

            // Auto-continue for uncaught syscalls
            match &reason {
                StopReason::SyscallEntry { number, .. }
                | StopReason::SyscallExit { number, .. } => {
                    if !self.catch_all_syscalls && !self.caught_syscalls.contains(number) {
                        continue; // Not a caught syscall, keep going
                    }
                }
                _ => {}
            }

            return Ok(reason);
        }
    }

    /// Execute a single machine instruction.
    pub fn step_instruction(&mut self) -> Result<StopReason> {
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
    pub fn step_in(&mut self) -> Result<StopReason> {
        let start_loc = self.source_location()?;

        loop {
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

    /// Source-level step over: step one source line, skipping over calls.
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
                            continue;
                        }
                        _ => return Ok(reason),
                    }
                }
            }

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
    /// Uses DWARF CFI to find the return address when available,
    /// falling back to frame pointers (rbp) otherwise.
    pub fn step_out(&mut self) -> Result<StopReason> {
        let regs = self.read_registers()?;
        let pc = regs.pc();

        // Try CFI-based return address first
        let ret_addr = if let Some(unwinder) = &self.unwinder {
            let dwarf_regs = self.dwarf_register_snapshot(&regs);
            unwinder.return_address(
                pc,
                &dwarf_regs,
                &|addr, len| self.process.read_memory(VirtAddr(addr), len),
            )?
        } else {
            None
        };

        let ret_addr = match ret_addr {
            Some(addr) => VirtAddr(addr),
            None => {
                // Fallback: frame pointer method
                let rbp = regs.get("rbp")?;
                if rbp == 0 {
                    return Err(Error::Other(
                        "cannot step out: no CFI data and no frame pointer".into(),
                    ));
                }
                let bytes = self.read_memory(VirtAddr(rbp + 8), 8)?;
                VirtAddr(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
            }
        };

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

    // ── Stack unwinding ────────────────────────────────────────────

    /// Walk the call stack and return a backtrace.
    ///
    /// Each frame includes the PC, function name, and source location
    /// when available.
    pub fn backtrace(&self) -> Result<Vec<BacktraceFrame>> {
        let regs = self.read_registers()?;
        let pc = regs.pc();

        let unwinder = self
            .unwinder
            .as_ref()
            .ok_or_else(|| Error::Other("no unwind info available".into()))?;

        let dwarf_regs = self.dwarf_register_snapshot(&regs);
        let raw_frames = unwinder.walk_stack(
            pc,
            &dwarf_regs,
            &|addr, len| self.process.read_memory(VirtAddr(addr), len),
        )?;

        let mut bt = Vec::with_capacity(raw_frames.len());
        for (i, frame) in raw_frames.iter().enumerate() {
            let function = self
                .elf
                .find_symbol_at(frame.pc)
                .map(|s| s.name.clone())
                .or_else(|| {
                    self.dwarf
                        .as_ref()
                        .and_then(|d| d.find_function(frame.pc).ok().flatten())
                });
            let location = self
                .dwarf
                .as_ref()
                .and_then(|d| d.find_location(frame.pc).ok().flatten());

            bt.push(BacktraceFrame {
                index: i,
                pc: frame.pc,
                function,
                location,
            });
        }

        Ok(bt)
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

    // ── Watchpoints ─────────────────────────────────────────────────

    /// Set a hardware watchpoint.
    pub fn set_watchpoint(
        &mut self,
        addr: VirtAddr,
        wp_type: WatchpointType,
        size: WatchpointSize,
    ) -> Result<u32> {
        self.watchpoints
            .set(self.process.pid(), addr, wp_type, size)
    }

    /// Remove a watchpoint by ID.
    pub fn remove_watchpoint(&mut self, id: u32) -> Result<()> {
        self.watchpoints.remove(self.process.pid(), id)
    }

    /// List all active watchpoints.
    pub fn list_watchpoints(&self) -> Vec<&Watchpoint> {
        self.watchpoints.list()
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
    pub fn current_function(&self) -> Result<Option<String>> {
        let pc = VirtAddr(self.read_registers()?.pc());
        if let Some(sym) = self.elf.find_symbol_at(pc) {
            return Ok(Some(sym.name.clone()));
        }
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

    /// Handle a stop event (adjust PC, apply signal policy).
    fn handle_stop(&mut self, reason: &StopReason) -> Result<()> {
        match reason {
            StopReason::BreakpointHit { addr } => {
                let mut regs = self.read_registers()?;
                regs.set_pc(addr.addr());
                self.write_registers(&regs)?;
            }
            StopReason::Signal(sig) => {
                let policy = self.signal_policy(*sig);
                if policy.pass {
                    self.pending_signal = Some(*sig);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Get the signal handling policy for a signal.
    pub fn signal_policy(&self, sig: Signal) -> SignalPolicy {
        self.signal_policies
            .get(&sig)
            .copied()
            .unwrap_or_default()
    }

    /// Set the signal handling policy for a signal.
    pub fn set_signal_policy(&mut self, sig: Signal, policy: SignalPolicy) {
        self.signal_policies.insert(sig, policy);
    }

    /// Add a syscall to the catch set by number.
    pub fn catch_syscall(&mut self, number: u64) {
        self.caught_syscalls.insert(number);
    }

    /// Remove a syscall from the catch set.
    pub fn uncatch_syscall(&mut self, number: u64) {
        self.caught_syscalls.remove(&number);
    }

    /// Enable or disable catching all syscalls.
    pub fn set_catch_all_syscalls(&mut self, enable: bool) {
        self.catch_all_syscalls = enable;
    }

    /// Check if syscall catching is active.
    pub fn is_catching_syscalls(&self) -> bool {
        self.catch_all_syscalls || !self.caught_syscalls.is_empty()
    }

    /// Get the set of caught syscall numbers.
    pub fn caught_syscalls(&self) -> &HashSet<u64> {
        &self.caught_syscalls
    }

    /// Build a DWARF register snapshot from the current register values.
    /// Returns (DWARF register number, value) pairs for use with the unwinder.
    fn dwarf_register_snapshot(&self, regs: &Registers) -> Vec<(u16, u64)> {
        registers::REGISTERS
            .iter()
            .filter(|r| r.dwarf_id >= 0)
            .filter_map(|r| regs.get(r.name).ok().map(|v| (r.dwarf_id as u16, v)))
            .collect()
    }
}
