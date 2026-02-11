//! Linux x86_64 syscall name/number mapping.
//!
//! Corresponds to book Ch.11 (Signals and Syscalls).
//! Provides a lookup table for translating between syscall numbers
//! and human-readable names.

/// Get the syscall name for a given number on x86_64.
pub fn name(number: u64) -> Option<&'static str> {
    SYSCALLS
        .iter()
        .find(|&&(n, _)| n == number)
        .map(|&(_, name)| name)
}

/// Get the syscall number for a given name on x86_64.
pub fn number(name: &str) -> Option<u64> {
    SYSCALLS
        .iter()
        .find(|&&(_, n)| n.eq_ignore_ascii_case(name))
        .map(|&(num, _)| num)
}

/// Common Linux x86_64 syscall numbers and names.
/// Based on the x86_64 ABI (arch/x86/entry/syscalls/syscall_64.tbl).
const SYSCALLS: &[(u64, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (28, "madvise"),
    (32, "dup"),
    (33, "dup2"),
    (35, "nanosleep"),
    (39, "getpid"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (62, "kill"),
    (72, "fcntl"),
    (78, "getdents"),
    (79, "getcwd"),
    (80, "chdir"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (87, "unlink"),
    (89, "readlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (92, "chown"),
    (95, "umask"),
    (96, "gettimeofday"),
    (99, "sysinfo"),
    (102, "getuid"),
    (104, "getgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (110, "getppid"),
    (157, "prctl"),
    (158, "arch_prctl"),
    (186, "gettid"),
    (200, "tkill"),
    (202, "futex"),
    (218, "set_tid_address"),
    (228, "clock_gettime"),
    (231, "exit_group"),
    (233, "epoll_ctl"),
    (257, "openat"),
    (262, "newfstatat"),
    (272, "unlinkat"),
    (281, "epoll_pwait"),
    (293, "pipe2"),
    (302, "prlimit64"),
    (318, "getrandom"),
    (332, "statx"),
    (435, "clone3"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_number() {
        assert_eq!(name(0), Some("read"));
        assert_eq!(name(1), Some("write"));
        assert_eq!(name(59), Some("execve"));
        assert_eq!(name(60), Some("exit"));
        assert_eq!(name(9999), None);
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(number("read"), Some(0));
        assert_eq!(number("write"), Some(1));
        assert_eq!(number("execve"), Some(59));
        assert_eq!(number("nonexistent"), None);
    }

    #[test]
    fn case_insensitive_name_lookup() {
        assert_eq!(number("READ"), Some(0));
        assert_eq!(number("Write"), Some(1));
    }
}
