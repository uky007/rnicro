//! Enhanced syscall tracing with argument decoding.
//!
//! Provides strace-like output with human-readable argument formatting.
//! Decodes file descriptors, string pointers, flags, and sizes
//! per the x86_64 syscall ABI.

use crate::error::Result;

/// Syscall argument type for formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Signed integer.
    Int,
    /// Unsigned integer / generic.
    Uint,
    /// File descriptor.
    Fd,
    /// Pointer (displayed as hex).
    Ptr,
    /// Pointer to a NUL-terminated string (read from tracee memory).
    StringPtr,
    /// Size value.
    Size,
    /// Open flags (O_RDONLY, O_WRONLY, etc.).
    OpenFlags,
    /// File mode bits (permission).
    FileMode,
    /// mmap protection flags.
    MmapProt,
    /// mmap flags.
    MmapFlags,
    /// Signal number.
    Signal,
    /// Clock ID.
    ClockId,
    /// Unused / not applicable.
    Unused,
}

/// Syscall argument definition: name, number, and argument types.
pub struct SyscallDef {
    pub number: u64,
    pub name: &'static str,
    pub args: &'static [(&'static str, ArgType)],
    pub ret: ArgType,
}

/// Lookup table for common x86_64 syscalls and their argument types.
pub static SYSCALL_TABLE: &[SyscallDef] = &[
    SyscallDef {
        number: 0,
        name: "read",
        args: &[("fd", ArgType::Fd), ("buf", ArgType::Ptr), ("count", ArgType::Size)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 1,
        name: "write",
        args: &[("fd", ArgType::Fd), ("buf", ArgType::Ptr), ("count", ArgType::Size)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 2,
        name: "open",
        args: &[("pathname", ArgType::StringPtr), ("flags", ArgType::OpenFlags), ("mode", ArgType::FileMode)],
        ret: ArgType::Fd,
    },
    SyscallDef {
        number: 3,
        name: "close",
        args: &[("fd", ArgType::Fd)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 4,
        name: "stat",
        args: &[("pathname", ArgType::StringPtr), ("statbuf", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 5,
        name: "fstat",
        args: &[("fd", ArgType::Fd), ("statbuf", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 8,
        name: "lseek",
        args: &[("fd", ArgType::Fd), ("offset", ArgType::Int), ("whence", ArgType::Uint)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 9,
        name: "mmap",
        args: &[("addr", ArgType::Ptr), ("length", ArgType::Size), ("prot", ArgType::MmapProt), ("flags", ArgType::MmapFlags), ("fd", ArgType::Fd), ("offset", ArgType::Int)],
        ret: ArgType::Ptr,
    },
    SyscallDef {
        number: 10,
        name: "mprotect",
        args: &[("addr", ArgType::Ptr), ("len", ArgType::Size), ("prot", ArgType::MmapProt)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 11,
        name: "munmap",
        args: &[("addr", ArgType::Ptr), ("length", ArgType::Size)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 12,
        name: "brk",
        args: &[("addr", ArgType::Ptr)],
        ret: ArgType::Ptr,
    },
    SyscallDef {
        number: 21,
        name: "access",
        args: &[("pathname", ArgType::StringPtr), ("mode", ArgType::Uint)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 39,
        name: "getpid",
        args: &[],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 56,
        name: "clone",
        args: &[("flags", ArgType::Uint), ("stack", ArgType::Ptr), ("parent_tid", ArgType::Ptr), ("child_tid", ArgType::Ptr), ("tls", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 57,
        name: "fork",
        args: &[],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 59,
        name: "execve",
        args: &[("filename", ArgType::StringPtr), ("argv", ArgType::Ptr), ("envp", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 60,
        name: "exit",
        args: &[("status", ArgType::Int)],
        ret: ArgType::Unused,
    },
    SyscallDef {
        number: 61,
        name: "wait4",
        args: &[("pid", ArgType::Int), ("wstatus", ArgType::Ptr), ("options", ArgType::Uint), ("rusage", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 62,
        name: "kill",
        args: &[("pid", ArgType::Int), ("sig", ArgType::Signal)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 101,
        name: "ptrace",
        args: &[("request", ArgType::Uint), ("pid", ArgType::Int), ("addr", ArgType::Ptr), ("data", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 228,
        name: "clock_gettime",
        args: &[("clk_id", ArgType::ClockId), ("tp", ArgType::Ptr)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 231,
        name: "exit_group",
        args: &[("status", ArgType::Int)],
        ret: ArgType::Unused,
    },
    SyscallDef {
        number: 257,
        name: "openat",
        args: &[("dirfd", ArgType::Fd), ("pathname", ArgType::StringPtr), ("flags", ArgType::OpenFlags), ("mode", ArgType::FileMode)],
        ret: ArgType::Fd,
    },
    SyscallDef {
        number: 262,
        name: "newfstatat",
        args: &[("dirfd", ArgType::Fd), ("pathname", ArgType::StringPtr), ("statbuf", ArgType::Ptr), ("flag", ArgType::Uint)],
        ret: ArgType::Int,
    },
    SyscallDef {
        number: 302,
        name: "prlimit64",
        args: &[("pid", ArgType::Int), ("resource", ArgType::Uint), ("new_rlim", ArgType::Ptr), ("old_rlim", ArgType::Ptr)],
        ret: ArgType::Int,
    },
];

/// Lookup a syscall definition by number.
pub fn lookup(number: u64) -> Option<&'static SyscallDef> {
    SYSCALL_TABLE.iter().find(|s| s.number == number)
}

/// Format a single argument value based on its type.
///
/// For StringPtr, `read_string` is called to read the string from tracee memory.
pub fn format_arg<F>(value: u64, arg_type: ArgType, read_string: &F) -> String
where
    F: Fn(u64) -> Result<String>,
{
    match arg_type {
        ArgType::Int => {
            let signed = value as i64;
            if signed < 0 {
                format!("{}", signed)
            } else {
                format!("{}", value)
            }
        }
        ArgType::Uint => format!("{}", value),
        ArgType::Fd => {
            match value as i32 {
                0 => "0<stdin>".to_string(),
                1 => "1<stdout>".to_string(),
                2 => "2<stderr>".to_string(),
                -100 => "AT_FDCWD".to_string(),
                n => format!("{}", n),
            }
        }
        ArgType::Ptr => {
            if value == 0 {
                "NULL".to_string()
            } else {
                format!("0x{:x}", value)
            }
        }
        ArgType::StringPtr => {
            if value == 0 {
                "NULL".to_string()
            } else {
                match read_string(value) {
                    Ok(s) => {
                        let truncated = if s.len() > 64 {
                            format!("\"{}\"...", &s[..64])
                        } else {
                            format!("\"{}\"", s)
                        };
                        truncated
                    }
                    Err(_) => format!("0x{:x}", value),
                }
            }
        }
        ArgType::Size => format!("{}", value),
        ArgType::OpenFlags => format_open_flags(value as u32),
        ArgType::FileMode => format!("0{:o}", value),
        ArgType::MmapProt => format_mmap_prot(value as u32),
        ArgType::MmapFlags => format_mmap_flags(value as u32),
        ArgType::Signal => {
            match value {
                1 => "SIGHUP".to_string(),
                2 => "SIGINT".to_string(),
                3 => "SIGQUIT".to_string(),
                6 => "SIGABRT".to_string(),
                9 => "SIGKILL".to_string(),
                11 => "SIGSEGV".to_string(),
                13 => "SIGPIPE".to_string(),
                14 => "SIGALRM".to_string(),
                15 => "SIGTERM".to_string(),
                n => format!("{}", n),
            }
        }
        ArgType::ClockId => {
            match value {
                0 => "CLOCK_REALTIME".to_string(),
                1 => "CLOCK_MONOTONIC".to_string(),
                n => format!("{}", n),
            }
        }
        ArgType::Unused => "?".to_string(),
    }
}

/// Format open() flags.
fn format_open_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    let access = flags & 0x3;
    match access {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => {}
    }
    if flags & 0x40 != 0 { parts.push("O_CREAT"); }
    if flags & 0x80 != 0 { parts.push("O_EXCL"); }
    if flags & 0x200 != 0 { parts.push("O_TRUNC"); }
    if flags & 0x400 != 0 { parts.push("O_APPEND"); }
    if flags & 0x800 != 0 { parts.push("O_NONBLOCK"); }
    if flags & 0x80000 != 0 { parts.push("O_CLOEXEC"); }

    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        parts.join("|")
    }
}

/// Format mmap protection flags.
fn format_mmap_prot(prot: u32) -> String {
    if prot == 0 {
        return "PROT_NONE".to_string();
    }
    let mut parts = Vec::new();
    if prot & 0x1 != 0 { parts.push("PROT_READ"); }
    if prot & 0x2 != 0 { parts.push("PROT_WRITE"); }
    if prot & 0x4 != 0 { parts.push("PROT_EXEC"); }
    parts.join("|")
}

/// Format mmap flags.
fn format_mmap_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 { parts.push("MAP_SHARED"); }
    if flags & 0x02 != 0 { parts.push("MAP_PRIVATE"); }
    if flags & 0x10 != 0 { parts.push("MAP_FIXED"); }
    if flags & 0x20 != 0 { parts.push("MAP_ANONYMOUS"); }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        parts.join("|")
    }
}

/// Format a complete syscall entry with decoded arguments.
pub fn format_syscall_entry<F>(
    number: u64,
    args: &[u64; 6],
    read_string: &F,
) -> String
where
    F: Fn(u64) -> Result<String>,
{
    let def = lookup(number);
    let name = def.map(|d| d.name).unwrap_or("unknown");

    let formatted_args: Vec<String> = if let Some(def) = def {
        def.args
            .iter()
            .enumerate()
            .map(|(i, (param_name, arg_type))| {
                let val = args.get(i).copied().unwrap_or(0);
                format!("{}={}", param_name, format_arg(val, *arg_type, read_string))
            })
            .collect()
    } else {
        args.iter().map(|a| format!("0x{:x}", a)).collect()
    };

    format!("{}({})", name, formatted_args.join(", "))
}

/// Format a syscall return value.
pub fn format_syscall_return(number: u64, retval: i64) -> String {
    let def = lookup(number);
    let ret_type = def.map(|d| d.ret).unwrap_or(ArgType::Int);

    match ret_type {
        ArgType::Ptr => {
            if retval < 0 {
                format!("{} ({})", retval, errno_name(-retval as u32))
            } else {
                format!("0x{:x}", retval as u64)
            }
        }
        ArgType::Fd => {
            if retval < 0 {
                format!("{} ({})", retval, errno_name(-retval as u32))
            } else {
                format!("{}", retval)
            }
        }
        _ => {
            if retval < 0 {
                format!("{} ({})", retval, errno_name(-retval as u32))
            } else {
                format!("{}", retval)
            }
        }
    }
}

/// Map common errno values to names.
fn errno_name(errno: u32) -> &'static str {
    match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        9 => "EBADF",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        17 => "EEXIST",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        28 => "ENOSPC",
        38 => "ENOSYS",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_read(_addr: u64) -> Result<String> {
        Err(crate::error::Error::Other("no read".into()))
    }

    #[test]
    fn lookup_known_syscall() {
        let def = lookup(1).unwrap();
        assert_eq!(def.name, "write");
        assert_eq!(def.args.len(), 3);
    }

    #[test]
    fn lookup_unknown_syscall() {
        assert!(lookup(99999).is_none());
    }

    #[test]
    fn format_fd_args() {
        assert_eq!(format_arg(0, ArgType::Fd, &no_read), "0<stdin>");
        assert_eq!(format_arg(1, ArgType::Fd, &no_read), "1<stdout>");
        assert_eq!(format_arg(2, ArgType::Fd, &no_read), "2<stderr>");
        assert_eq!(format_arg(5, ArgType::Fd, &no_read), "5");
    }

    #[test]
    fn format_ptr_null() {
        assert_eq!(format_arg(0, ArgType::Ptr, &no_read), "NULL");
        assert_eq!(format_arg(0x1000, ArgType::Ptr, &no_read), "0x1000");
    }

    #[test]
    fn format_open_flags_rdonly() {
        assert_eq!(format_open_flags(0), "O_RDONLY");
    }

    #[test]
    fn format_open_flags_combined() {
        // O_WRONLY | O_CREAT | O_TRUNC = 0x1 | 0x40 | 0x200 = 0x241
        let result = format_open_flags(0x241);
        assert!(result.contains("O_WRONLY"));
        assert!(result.contains("O_CREAT"));
        assert!(result.contains("O_TRUNC"));
    }

    #[test]
    fn format_mmap_prot_rwx() {
        let result = format_mmap_prot(0x7); // PROT_READ | PROT_WRITE | PROT_EXEC
        assert!(result.contains("PROT_READ"));
        assert!(result.contains("PROT_WRITE"));
        assert!(result.contains("PROT_EXEC"));
    }

    #[test]
    fn format_mmap_prot_none() {
        assert_eq!(format_mmap_prot(0), "PROT_NONE");
    }

    #[test]
    fn format_syscall_entry_write() {
        let args = [1u64, 0x7fff0000, 13, 0, 0, 0];
        let result = format_syscall_entry(1, &args, &no_read);
        assert!(result.starts_with("write("));
        assert!(result.contains("fd=1<stdout>"));
        assert!(result.contains("count=13"));
    }

    #[test]
    fn format_return_error() {
        let result = format_syscall_return(2, -2);
        assert!(result.contains("ENOENT"));
    }

    #[test]
    fn format_return_success() {
        let result = format_syscall_return(0, 100);
        assert_eq!(result, "100");
    }

    #[test]
    fn format_string_ptr_with_reader() {
        let reader = |_addr: u64| -> Result<String> { Ok("hello.txt".to_string()) };
        let result = format_arg(0x1000, ArgType::StringPtr, &reader);
        assert_eq!(result, "\"hello.txt\"");
    }

    #[test]
    fn format_signal() {
        assert_eq!(format_arg(9, ArgType::Signal, &no_read), "SIGKILL");
        assert_eq!(format_arg(11, ArgType::Signal, &no_read), "SIGSEGV");
        assert_eq!(format_arg(99, ArgType::Signal, &no_read), "99");
    }
}
