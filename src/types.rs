use std::fmt;

/// Virtual address in the running process (post-ASLR).
///
/// This is the address as seen at runtime. For PIE binaries,
/// this differs from the file address by the load bias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    pub fn addr(self) -> u64 {
        self.0
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl std::ops::Add<u64> for VirtAddr {
    type Output = VirtAddr;
    fn add(self, rhs: u64) -> Self::Output {
        VirtAddr(self.0 + rhs)
    }
}

impl std::ops::Sub<u64> for VirtAddr {
    type Output = VirtAddr;
    fn sub(self, rhs: u64) -> Self::Output {
        VirtAddr(self.0 - rhs)
    }
}

/// Stop reason reported by the debugger after waiting on the tracee.
///
/// Mirrors sdb's stop_reason, classifying why the process stopped.
#[derive(Debug, Clone)]
pub enum StopReason {
    /// Hit a software or hardware breakpoint.
    BreakpointHit { addr: VirtAddr },
    /// Completed a single-step.
    SingleStep,
    /// Received a signal (other than SIGTRAP).
    Signal(nix::sys::signal::Signal),
    /// Stopped at a syscall entry.
    SyscallEntry {
        number: u64,
        args: [u64; 6],
    },
    /// Stopped at a syscall exit.
    SyscallExit {
        number: u64,
        retval: i64,
    },
    /// Process exited normally.
    Exited(i32),
    /// Process was killed by a signal.
    Terminated(nix::sys::signal::Signal),
    /// A new thread was created (clone event).
    ThreadCreated(nix::unistd::Pid),
}

/// Process execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virt_addr_display() {
        let addr = VirtAddr(0x400000);
        assert_eq!(format!("{}", addr), "0x400000");
    }

    #[test]
    fn virt_addr_arithmetic() {
        let addr = VirtAddr(0x1000);
        assert_eq!((addr + 0x10).addr(), 0x1010);
        assert_eq!((addr - 0x10).addr(), 0x0FF0);
    }

    #[test]
    fn virt_addr_ord() {
        let a = VirtAddr(0x100);
        let b = VirtAddr(0x200);
        assert!(a < b);
        assert_eq!(a, VirtAddr(0x100));
    }

    #[test]
    fn virt_addr_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VirtAddr(0x1000));
        set.insert(VirtAddr(0x2000));
        set.insert(VirtAddr(0x1000)); // duplicate
        assert_eq!(set.len(), 2);
    }
}
