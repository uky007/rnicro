//! Process control via ptrace.
//!
//! Corresponds to sdb's process.hpp/cpp and book Ch.3 (Attaching to a Process).
//! Handles launching/attaching to a tracee, waiting for events,
//! and basic execution control (continue, single-step).

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, execvp, ForkResult, Pid};
use std::ffi::CString;
use std::path::Path;

use crate::error::{Error, Result};
use crate::types::{ProcessState, StopReason, VirtAddr};

/// A debugged process controlled via ptrace.
pub struct Process {
    pid: Pid,
    state: ProcessState,
    terminate_on_end: bool,
    is_attached: bool,
}

impl Process {
    /// Launch a new process under ptrace control.
    ///
    /// Forks, calls PTRACE_TRACEME in the child, then execs the given program.
    /// The parent waits for the initial SIGTRAP (caused by exec) before returning.
    pub fn launch(program: &Path, args: &[&str]) -> Result<Self> {
        let prog = CString::new(program.to_str().ok_or_else(|| {
            Error::Process("invalid program path".into())
        })?)
        .map_err(|e| Error::Process(e.to_string()))?;

        let c_args: Vec<CString> = std::iter::once(prog.clone())
            .chain(args.iter().map(|a| CString::new(*a).unwrap()))
            .collect();
        let c_args_ref: Vec<&std::ffi::CStr> = c_args.iter().map(|a| a.as_c_str()).collect();

        match unsafe { fork() }.map_err(|e| Error::Process(e.to_string()))? {
            ForkResult::Child => {
                // Child: request tracing, then exec
                ptrace::traceme()?;
                execvp(&prog, &c_args_ref)
                    .map_err(|e| Error::Process(format!("execvp failed: {}", e)))?;
                unreachable!();
            }
            ForkResult::Parent { child } => {
                // Parent: wait for the child to stop at exec
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

                // Set ptrace options for tracking clones/forks/execs
                ptrace::setoptions(
                    child,
                    ptrace::Options::PTRACE_O_TRACECLONE,
                )?;

                Ok(Process {
                    pid: child,
                    state: ProcessState::Stopped,
                    terminate_on_end: true,
                    is_attached: true,
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

        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACECLONE)?;

        Ok(Process {
            pid,
            state: ProcessState::Stopped,
            terminate_on_end: false,
            is_attached: true,
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
