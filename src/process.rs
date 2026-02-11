//! Process control via ptrace.
//!
//! Corresponds to sdb's process.hpp/cpp and book Ch.3-4
//! (Attaching to a Process; Pipes, procfs, and Automated Testing).
//!
//! Handles launching/attaching to a tracee, waiting for events,
//! and basic execution control (continue, single-step).
//! Uses a pipe to synchronize fork/exec (Ch.4 pattern).

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, execvp, ForkResult, Pid};
use std::ffi::CString;
use std::path::Path;

use crate::error::{Error, Result};
use crate::pipe::Channel;
use crate::types::{ProcessState, StopReason, VirtAddr};

// ── Debug register access via PTRACE_PEEKUSER / PTRACE_POKEUSER ──────

/// Offset of `u_debugreg` within `struct user` (bytes).
fn debug_reg_offset(reg: usize) -> u64 {
    // offsetof(struct user, u_debugreg) + reg * 8
    // On x86_64, u_debugreg starts at offset 848 in struct user.
    const U_DEBUGREG_OFFSET: u64 = 848;
    U_DEBUGREG_OFFSET + (reg as u64) * 8
}

/// Read a debug register (DR0–DR7) from the tracee.
pub fn read_debug_reg(pid: Pid, reg: usize) -> Result<u64> {
    if reg > 7 || reg == 4 || reg == 5 {
        return Err(Error::Other(format!("invalid debug register: DR{}", reg)));
    }
    let offset = debug_reg_offset(reg);
    let val = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKUSER,
            pid.as_raw() as libc::c_uint,
            offset as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if val == -1 {
        let errno = nix::errno::Errno::last();
        if errno != nix::errno::Errno::UnknownErrno {
            return Err(Error::Other(format!(
                "PTRACE_PEEKUSER DR{}: {}",
                reg, errno
            )));
        }
    }
    Ok(val as u64)
}

/// Write a debug register (DR0–DR7) in the tracee.
pub fn write_debug_reg(pid: Pid, reg: usize, value: u64) -> Result<()> {
    if reg > 7 || reg == 4 || reg == 5 {
        return Err(Error::Other(format!("invalid debug register: DR{}", reg)));
    }
    let offset = debug_reg_offset(reg);
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid.as_raw() as libc::c_uint,
            offset as *mut libc::c_void,
            value as *mut libc::c_void,
        )
    };
    if ret == -1 {
        let errno = nix::errno::Errno::last();
        return Err(Error::Other(format!(
            "PTRACE_POKEUSER DR{}: {}",
            reg, errno
        )));
    }
    Ok(())
}

/// A debugged process controlled via ptrace.
pub struct Process {
    pid: Pid,
    state: ProcessState,
    terminate_on_end: bool,
    is_attached: bool,
    /// Tracks whether we're between syscall entry and exit.
    expecting_syscall_exit: bool,
}

impl Process {
    /// Launch a new process under ptrace control.
    ///
    /// Forks, calls `PTRACE_TRACEME` in the child, then execs the given program.
    /// A pipe synchronizes the parent and child so that `traceme` is guaranteed
    /// to complete before the parent calls `waitpid` (Ch.4 pattern from sdb).
    pub fn launch(program: &Path, args: &[&str]) -> Result<Self> {
        let prog = CString::new(program.to_str().ok_or_else(|| {
            Error::Process("invalid program path".into())
        })?)
        .map_err(|e| Error::Process(e.to_string()))?;

        let c_args: Vec<CString> = std::iter::once(prog.clone())
            .chain(args.iter().map(|a| CString::new(*a).unwrap()))
            .collect();
        let c_args_ref: Vec<&std::ffi::CStr> = c_args.iter().map(|a| a.as_c_str()).collect();

        // Pipe for synchronization: child notifies parent after traceme
        let channel = Channel::new()?;

        match unsafe { fork() }.map_err(|e| Error::Process(e.to_string()))? {
            ForkResult::Child => {
                channel.close_read();

                // Request tracing
                ptrace::traceme()?;

                // Notify parent that traceme succeeded
                let _ = channel.notify();
                channel.close_write();

                // Replace process image
                execvp(&prog, &c_args_ref)
                    .map_err(|e| Error::Process(format!("execvp failed: {}", e)))?;
                unreachable!();
            }
            ForkResult::Parent { child } => {
                channel.close_write();

                // Wait for child to complete traceme before proceeding
                channel.wait()?;
                channel.close_read();

                // Wait for the child to stop at exec (SIGTRAP)
                let status = waitpid(child, None)
                    .map_err(|e| Error::Process(format!("waitpid failed: {}", e)))?;

                match status {
                    WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
                    other => {
                        return Err(Error::Process(format!(
                            "unexpected status after launch: {:?}",
                            other
                        )));
                    }
                }

                // Set ptrace options for tracking clones/forks/execs and syscall stops
                ptrace::setoptions(
                    child,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACESYSGOOD,
                )?;

                Ok(Process {
                    pid: child,
                    state: ProcessState::Stopped,
                    terminate_on_end: true,
                    is_attached: true,
                    expecting_syscall_exit: false,
                })
            }
        }
    }

    /// Attach to an already-running process.
    pub fn attach(pid: Pid) -> Result<Self> {
        ptrace::attach(pid)?;

        match waitpid(pid, None)
            .map_err(|e| Error::Process(format!("waitpid after attach: {}", e)))?
        {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
            other => {
                return Err(Error::Process(format!(
                    "unexpected status after attach: {:?}",
                    other
                )));
            }
        }

        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )?;

        Ok(Process {
            pid,
            state: ProcessState::Stopped,
            terminate_on_end: false,
            is_attached: true,
            expecting_syscall_exit: false,
        })
    }

    /// Resume execution of the tracee.
    pub fn resume(&mut self) -> Result<()> {
        ptrace::cont(self.pid, None)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    /// Resume execution, delivering a signal to the tracee.
    pub fn resume_with_signal(&mut self, sig: Signal) -> Result<()> {
        ptrace::cont(self.pid, Some(sig))?;
        self.state = ProcessState::Running;
        Ok(())
    }

    /// Resume execution, stopping at the next syscall entry/exit.
    pub fn resume_with_syscall_trap(&mut self, sig: Option<Signal>) -> Result<()> {
        ptrace::syscall(self.pid, sig)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    /// Execute a single instruction.
    pub fn step_instruction(&mut self) -> Result<()> {
        ptrace::step(self.pid, None)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    /// Wait for the tracee to stop and classify the reason.
    pub fn wait_on_signal(&mut self) -> Result<StopReason> {
        let status = waitpid(self.pid, None)
            .map_err(|e| Error::Process(format!("waitpid: {}", e)))?;

        let reason = match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                self.state = ProcessState::Stopped;
                self.classify_sigtrap()?
            }
            WaitStatus::Stopped(_, sig) => {
                self.state = ProcessState::Stopped;
                StopReason::Signal(sig)
            }
            WaitStatus::Exited(_, code) => {
                self.state = ProcessState::Exited;
                self.is_attached = false;
                StopReason::Exited(code)
            }
            WaitStatus::Signaled(_, sig, _) => {
                self.state = ProcessState::Terminated;
                self.is_attached = false;
                StopReason::Terminated(sig)
            }
            WaitStatus::PtraceSyscall(_) => {
                self.state = ProcessState::Stopped;
                self.classify_syscall()?
            }
            WaitStatus::PtraceEvent(_, _, event) => {
                self.state = ProcessState::Stopped;
                if event == libc::PTRACE_EVENT_CLONE as i32 {
                    let new_pid = ptrace::getevent(self.pid)
                        .map_err(|e| Error::Process(format!("getevent: {}", e)))?;
                    StopReason::ThreadCreated(Pid::from_raw(new_pid as i32))
                } else {
                    StopReason::SingleStep
                }
            }
            other => {
                return Err(Error::Process(format!(
                    "unexpected wait status: {:?}",
                    other
                )));
            }
        };

        Ok(reason)
    }

    /// Read a word (8 bytes) from the tracee's memory.
    pub fn read_memory_word(&self, addr: VirtAddr) -> Result<u64> {
        let val = ptrace::read(self.pid, addr.addr() as *mut libc::c_void)?;
        Ok(val as u64)
    }

    /// Write a word (8 bytes) to the tracee's memory.
    pub fn write_memory_word(&self, addr: VirtAddr, data: u64) -> Result<()> {
        ptrace::write(
            self.pid,
            addr.addr() as *mut libc::c_void,
            data as libc::c_long,
        )?;
        Ok(())
    }

    /// Read arbitrary bytes from tracee memory via /proc/pid/mem.
    pub fn read_memory(&self, addr: VirtAddr, len: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(format!("/proc/{}/mem", self.pid))
            .map_err(|e| Error::Process(format!("/proc/pid/mem: {}", e)))?;
        file.seek(SeekFrom::Start(addr.addr()))?;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Get the process ID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Get the current process state.
    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// Classify a syscall stop as entry or exit.
    fn classify_syscall(&mut self) -> Result<StopReason> {
        let regs = ptrace::getregs(self.pid)?;
        if self.expecting_syscall_exit {
            self.expecting_syscall_exit = false;
            Ok(StopReason::SyscallExit {
                number: regs.orig_rax,
                retval: regs.rax as i64,
            })
        } else {
            self.expecting_syscall_exit = true;
            Ok(StopReason::SyscallEntry {
                number: regs.orig_rax,
                args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
            })
        }
    }

    /// Classify a SIGTRAP into a more specific stop reason.
    fn classify_sigtrap(&self) -> Result<StopReason> {
        // Use PTRACE_GETSIGINFO to distinguish breakpoint from single-step.
        let siginfo = ptrace::getsiginfo(self.pid)?;

        match siginfo.si_code {
            // SI_KERNEL (0x80) or TRAP_BRKPT (1): software breakpoint
            0x80 | 1 => {
                let regs = ptrace::getregs(self.pid)?;
                // INT3 advances RIP past the 0xCC byte, so the BP address is rip-1
                let bp_addr = VirtAddr(regs.rip - 1);
                Ok(StopReason::BreakpointHit { addr: bp_addr })
            }
            // TRAP_TRACE (2): single-step
            2 => Ok(StopReason::SingleStep),
            // TRAP_HWBKPT (4): hardware watchpoint/breakpoint
            4 => {
                // Read DR6 to find which slot triggered
                let dr6 = read_debug_reg(self.pid, 6)?;
                for i in 0..4 {
                    if dr6 & (1 << i) != 0 {
                        let addr = read_debug_reg(self.pid, i)?;
                        // Clear DR6 status bits
                        write_debug_reg(self.pid, 6, 0)?;
                        return Ok(StopReason::WatchpointHit {
                            slot: i,
                            addr: VirtAddr(addr),
                        });
                    }
                }
                // DR6 didn't identify a slot; treat as single-step
                Ok(StopReason::SingleStep)
            }
            _ => Ok(StopReason::SingleStep),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.is_attached {
            if self.terminate_on_end {
                let _ = nix::sys::signal::kill(self.pid, Signal::SIGKILL);
                let _ = waitpid(self.pid, None);
            } else {
                let _ = ptrace::detach(self.pid, None);
            }
        }
    }
}
