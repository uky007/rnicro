//! Runtime anti-analysis bypass engine.
//!
//! Detects anti-debugging techniques at runtime (via syscall interception)
//! and automatically neutralizes them by modifying syscall arguments or
//! return values. All bypass actions are recorded in the event log.
//!
//! # Supported bypass techniques
//!
//! | Technique | Detection | Bypass |
//! |-----------|-----------|--------|
//! | `ptrace(TRACEME)` | syscall 101, arg0=0 | Rewrite rax to 0 on exit |
//! | `/proc/self/status` read | `openat`/`open` with path match | Track fd, spoof `TracerPid` on read |
//! | `prctl(PR_SET_DUMPABLE, 0)` | syscall 157, arg0=4, arg1=0 | Rewrite arg1 to 1 |
//! | Timing checks (RDTSC) | Detected statically | NOP patch at addresses |
//! | INT3 self-check | Non-breakpoint SIGTRAP | Auto-continue |
//! | `kill(getpid(), sig)` | Self-signal via kill/tgkill/tkill | Suppress or transparent pass |
//! | `alarm(N)` | Watchdog timer (SIGALRM) | Neutralize (return 0, no timer) |
//! | `setitimer(ITIMER_REAL)` | Interval watchdog timer | Neutralize (return 0, no timer) |
//! | `rt_sigaction(sig, handler)` | Signal handler registration | Log and optionally block |

use std::collections::HashSet;

use crate::event_log::{EventKind, EventLog};
use crate::types::VirtAddr;

// Linux syscall numbers (x86_64)
const SYS_READ: u64 = 0;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_ALARM: u64 = 37;
const SYS_SETITIMER: u64 = 38;
const _SYS_GETPID: u64 = 39; // reference: tracee calls getpid() to get its own PID
const SYS_KILL: u64 = 62;
const SYS_PTRACE: u64 = 101;
const SYS_PRCTL: u64 = 157;
const _SYS_GETTID: u64 = 186; // reference: thread ID for tkill detection
const SYS_TKILL: u64 = 200;
const SYS_TGKILL: u64 = 234;
const SYS_OPENAT: u64 = 257;

// ptrace request constants
const PTRACE_TRACEME: u64 = 0;

// prctl constants
const PR_SET_DUMPABLE: u64 = 4;

// Signals
const SIGALRM: u64 = 14;
const SIGTERM: u64 = 15;
const SIGCHLD: u64 = 17;

/// Actions the bypass engine can take on a syscall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassAction {
    /// No action needed — syscall is benign.
    None,
    /// Rewrite the syscall return value (rax) to this value on exit.
    FakeReturnValue(i64),
    /// Rewrite a syscall argument register before the syscall executes.
    RewriteArg { arg_index: usize, new_value: u64 },
    /// Track this file descriptor as pointing to a sensitive proc file.
    TrackProcFd,
    /// The read buffer for a tracked proc fd needs TracerPid spoofing.
    SpoofTracerPid,
    /// Skip (auto-continue) an INT3 that isn't a user breakpoint.
    SkipInt3,
    /// Skip the syscall entirely (set syscall number to -1 via orig_rax).
    SkipSyscall,
}

/// Signal bypass policy for a specific signal number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalBypassPolicy {
    /// Do nothing — let the debugger's default policy handle it.
    Default,
    /// Transparently pass the signal to the tracee without stopping.
    TransparentPass,
    /// Suppress the signal entirely (do not deliver).
    Suppress,
}

/// Configuration for the bypass engine.
#[derive(Debug, Clone)]
pub struct BypassEngineConfig {
    /// Bypass ptrace(TRACEME) self-trace checks.
    pub bypass_ptrace: bool,
    /// Bypass /proc/self/status TracerPid checks.
    pub bypass_proc_status: bool,
    /// Bypass prctl(PR_SET_DUMPABLE, 0).
    pub bypass_prctl_dumpable: bool,
    /// Auto-skip INT3 traps at non-breakpoint addresses.
    pub skip_int3_traps: bool,
    /// Patch RDTSC instructions with NOPs.
    pub patch_rdtsc: bool,
    /// Neutralize alarm() and setitimer() watchdog timers.
    pub neutralize_watchdog_timers: bool,
    /// Suppress self-sent signals (kill(getpid(), sig) / tgkill / tkill).
    pub suppress_self_signals: bool,
    /// Log rt_sigaction() handler registrations.
    pub log_signal_handlers: bool,
}

impl Default for BypassEngineConfig {
    fn default() -> Self {
        Self {
            bypass_ptrace: true,
            bypass_proc_status: true,
            bypass_prctl_dumpable: true,
            skip_int3_traps: true,
            patch_rdtsc: false, // Off by default — requires memory write
            neutralize_watchdog_timers: true,
            suppress_self_signals: true,
            log_signal_handlers: true,
        }
    }
}

/// Runtime anti-analysis bypass engine.
///
/// Sits between the process and the debugger, inspecting syscall
/// entry/exit events and deciding whether to modify them.
#[derive(Debug)]
pub struct BypassEngine {
    config: BypassEngineConfig,
    /// File descriptors opened to /proc/self/status (tracked for read spoofing).
    proc_status_fds: HashSet<i32>,
    /// Pending actions to apply on syscall exit (keyed by syscall number at entry).
    pending_exit_action: Option<PendingAction>,
    /// Statistics.
    stats: BypassStats,
    /// The tracee's PID (for detecting self-signals).
    tracee_pid: i32,
    /// The tracee's TID (main thread, for detecting self-signals).
    tracee_tid: i32,
    /// Signal bypass policies per signal number.
    signal_policies: std::collections::HashMap<u64, SignalBypassPolicy>,
}

/// A pending action to apply when the matched syscall exits.
#[derive(Debug, Clone)]
struct PendingAction {
    syscall_number: u64,
    action: BypassAction,
    technique: &'static str,
    detail: String,
}

/// Statistics on bypass actions taken.
#[derive(Debug, Clone, Default)]
pub struct BypassStats {
    pub ptrace_bypassed: u64,
    pub proc_status_spoofed: u64,
    pub prctl_rewritten: u64,
    pub int3_skipped: u64,
    pub rdtsc_patched: u64,
    pub timers_neutralized: u64,
    pub self_signals_suppressed: u64,
    pub signal_handlers_logged: u64,
}

impl BypassEngine {
    /// Create a new bypass engine with the given configuration.
    pub fn new(config: BypassEngineConfig) -> Self {
        Self {
            config,
            proc_status_fds: HashSet::new(),
            pending_exit_action: None,
            stats: BypassStats::default(),
            tracee_pid: 0,
            tracee_tid: 0,
            signal_policies: std::collections::HashMap::new(),
        }
    }

    /// Create a bypass engine with all bypasses enabled.
    pub fn all_enabled() -> Self {
        Self::new(BypassEngineConfig {
            bypass_ptrace: true,
            bypass_proc_status: true,
            bypass_prctl_dumpable: true,
            skip_int3_traps: true,
            patch_rdtsc: true,
            neutralize_watchdog_timers: true,
            suppress_self_signals: true,
            log_signal_handlers: true,
        })
    }

    /// Set the tracee's PID and TID (call after launch/attach).
    pub fn set_tracee_ids(&mut self, pid: i32, tid: i32) {
        self.tracee_pid = pid;
        self.tracee_tid = tid;
    }

    /// Set a signal bypass policy for a specific signal number.
    pub fn set_signal_policy(&mut self, signal: u64, policy: SignalBypassPolicy) {
        self.signal_policies.insert(signal, policy);
    }

    /// Get the signal bypass policy for a signal number.
    pub fn signal_policy(&self, signal: u64) -> SignalBypassPolicy {
        self.signal_policies
            .get(&signal)
            .copied()
            .unwrap_or(SignalBypassPolicy::Default)
    }

    /// Get the configuration (mutable).
    pub fn config_mut(&mut self) -> &mut BypassEngineConfig {
        &mut self.config
    }

    /// Get the configuration.
    pub fn config(&self) -> &BypassEngineConfig {
        &self.config
    }

    /// Get bypass statistics.
    pub fn stats(&self) -> &BypassStats {
        &self.stats
    }

    /// Evaluate a syscall entry and decide what action to take.
    ///
    /// Call this when a `SyscallEntry` stop is received. Returns the action
    /// to apply immediately (for arg rewriting) and stores a pending action
    /// for syscall exit (for return value faking).
    ///
    /// `read_string` is a closure that reads a NUL-terminated string from
    /// the tracee's memory at the given address.
    pub fn on_syscall_entry<F>(
        &mut self,
        number: u64,
        args: &[u64; 6],
        read_string: &F,
    ) -> BypassAction
    where
        F: Fn(u64) -> Option<String>,
    {
        self.pending_exit_action = None;

        // ptrace(PTRACE_TRACEME, ...)
        if self.config.bypass_ptrace && number == SYS_PTRACE && args[0] == PTRACE_TRACEME {
            self.pending_exit_action = Some(PendingAction {
                syscall_number: SYS_PTRACE,
                action: BypassAction::FakeReturnValue(0),
                technique: "ptrace(TRACEME)",
                detail: "intercepted ptrace(PTRACE_TRACEME), will return 0".into(),
            });
            return BypassAction::None; // Action on exit, not entry
        }

        // prctl(PR_SET_DUMPABLE, 0) → rewrite arg1 to 1
        if self.config.bypass_prctl_dumpable
            && number == SYS_PRCTL
            && args[0] == PR_SET_DUMPABLE
            && args[1] == 0
        {
            return BypassAction::RewriteArg {
                arg_index: 1,
                new_value: 1,
            };
        }

        // open/openat("/proc/self/status", ...) → track the fd on exit
        if self.config.bypass_proc_status
            && (number == SYS_OPEN || number == SYS_OPENAT)
        {
            let path_addr = if number == SYS_OPENAT { args[1] } else { args[0] };
            if let Some(path) = read_string(path_addr) {
                if path.contains("/proc/self/status")
                    || path.contains("/proc/self/maps")
                {
                    self.pending_exit_action = Some(PendingAction {
                        syscall_number: number,
                        action: BypassAction::TrackProcFd,
                        technique: "/proc/self/status check",
                        detail: format!("tracking fd from open(\"{}\")", path),
                    });
                }
            }
        }

        // read() on a tracked proc fd → spoof on exit
        if self.config.bypass_proc_status && number == SYS_READ {
            let fd = args[0] as i32;
            if self.proc_status_fds.contains(&fd) {
                self.pending_exit_action = Some(PendingAction {
                    syscall_number: SYS_READ,
                    action: BypassAction::SpoofTracerPid,
                    technique: "/proc/self/status check",
                    detail: format!("read(fd={}) from tracked proc file, will spoof TracerPid", fd),
                });
            }
        }

        // close() on a tracked proc fd → stop tracking
        if number == SYS_CLOSE {
            let fd = args[0] as i32;
            self.proc_status_fds.remove(&fd);
        }

        // ── Signal-based anti-analysis (Mirai-style) ──

        // alarm(seconds) → neutralize watchdog timer by skipping the syscall
        if self.config.neutralize_watchdog_timers && number == SYS_ALARM && args[0] > 0 {
            self.pending_exit_action = Some(PendingAction {
                syscall_number: SYS_ALARM,
                action: BypassAction::FakeReturnValue(0),
                technique: "alarm() watchdog",
                detail: format!("neutralized alarm({}) watchdog timer", args[0]),
            });
            return BypassAction::SkipSyscall;
        }

        // setitimer(ITIMER_REAL, ...) → neutralize interval watchdog
        // ITIMER_REAL = 0 → delivers SIGALRM
        if self.config.neutralize_watchdog_timers && number == SYS_SETITIMER && args[0] == 0 {
            self.pending_exit_action = Some(PendingAction {
                syscall_number: SYS_SETITIMER,
                action: BypassAction::FakeReturnValue(0),
                technique: "setitimer() watchdog",
                detail: "neutralized setitimer(ITIMER_REAL) watchdog timer".into(),
            });
            return BypassAction::SkipSyscall;
        }

        // kill(getpid(), sig) or kill(0, sig) → suppress self-signal
        if self.config.suppress_self_signals && number == SYS_KILL {
            let target_pid = args[0] as i32;
            let sig = args[1];
            if target_pid == self.tracee_pid || target_pid == 0 {
                if is_anti_debug_signal(sig) {
                    self.pending_exit_action = Some(PendingAction {
                        syscall_number: SYS_KILL,
                        action: BypassAction::FakeReturnValue(0),
                        technique: "self-signal (kill)",
                        detail: format!(
                            "suppressed kill({}, {}) self-signal",
                            target_pid,
                            signal_name(sig)
                        ),
                    });
                    return BypassAction::SkipSyscall;
                }
            }
        }

        // tgkill(tgid, tid, sig) → suppress self-signal
        if self.config.suppress_self_signals && number == SYS_TGKILL {
            let tgid = args[0] as i32;
            let sig = args[2];
            if tgid == self.tracee_pid && is_anti_debug_signal(sig) {
                self.pending_exit_action = Some(PendingAction {
                    syscall_number: SYS_TGKILL,
                    action: BypassAction::FakeReturnValue(0),
                    technique: "self-signal (tgkill)",
                    detail: format!(
                        "suppressed tgkill({}, {}, {}) self-signal",
                        tgid,
                        args[1] as i32,
                        signal_name(sig)
                    ),
                });
                return BypassAction::SkipSyscall;
            }
        }

        // tkill(tid, sig) → suppress self-signal
        if self.config.suppress_self_signals && number == SYS_TKILL {
            let tid = args[0] as i32;
            let sig = args[1];
            if tid == self.tracee_tid && is_anti_debug_signal(sig) {
                self.pending_exit_action = Some(PendingAction {
                    syscall_number: SYS_TKILL,
                    action: BypassAction::FakeReturnValue(0),
                    technique: "self-signal (tkill)",
                    detail: format!(
                        "suppressed tkill({}, {}) self-signal",
                        tid,
                        signal_name(sig)
                    ),
                });
                return BypassAction::SkipSyscall;
            }
        }

        // rt_sigaction(sig, act, oldact) → log handler registration
        if self.config.log_signal_handlers && number == SYS_RT_SIGACTION {
            let _sig = args[0];
            if args[1] != 0 {
                // act != NULL → new handler being installed
                self.stats.signal_handlers_logged += 1;
                // Don't block, just log — blocking can break normal operation
            }
        }

        BypassAction::None
    }

    /// Evaluate a syscall exit and decide what action to take.
    ///
    /// Call this when a `SyscallExit` stop is received. Returns the action
    /// to apply (return value rewriting, buffer spoofing, etc.) and records
    /// the bypass event in the log.
    pub fn on_syscall_exit(
        &mut self,
        number: u64,
        retval: i64,
        event_log: &mut EventLog,
    ) -> BypassAction {
        let pending = match self.pending_exit_action.take() {
            Some(p) if p.syscall_number == number => p,
            _ => return BypassAction::None,
        };

        match &pending.action {
            BypassAction::FakeReturnValue(fake_val) => {
                // Attribute to the correct counter
                match pending.syscall_number {
                    SYS_PTRACE => self.stats.ptrace_bypassed += 1,
                    SYS_ALARM | SYS_SETITIMER => self.stats.timers_neutralized += 1,
                    SYS_KILL | SYS_TGKILL | SYS_TKILL => {
                        self.stats.self_signals_suppressed += 1
                    }
                    _ => {}
                }
                event_log.record(EventKind::AntiDebugDetected {
                    technique: pending.technique.into(),
                    addr: None,
                    bypassed: true,
                    detail: pending.detail.clone(),
                });
                BypassAction::FakeReturnValue(*fake_val)
            }
            BypassAction::TrackProcFd => {
                if retval >= 0 {
                    self.proc_status_fds.insert(retval as i32);
                    event_log.record(EventKind::AntiDebugDetected {
                        technique: pending.technique.into(),
                        addr: None,
                        bypassed: true,
                        detail: format!("{}, fd={}", pending.detail, retval),
                    });
                }
                BypassAction::None // No modification needed yet
            }
            BypassAction::SpoofTracerPid => {
                if retval > 0 {
                    self.stats.proc_status_spoofed += 1;
                    event_log.record(EventKind::AntiDebugDetected {
                        technique: pending.technique.into(),
                        addr: None,
                        bypassed: true,
                        detail: pending.detail.clone(),
                    });
                    return BypassAction::SpoofTracerPid;
                }
                BypassAction::None
            }
            _ => BypassAction::None,
        }
    }

    /// Record a prctl arg rewrite event.
    pub fn record_prctl_bypass(&mut self, event_log: &mut EventLog) {
        self.stats.prctl_rewritten += 1;
        event_log.record(EventKind::AntiDebugDetected {
            technique: "prctl(PR_SET_DUMPABLE, 0)".into(),
            addr: None,
            bypassed: true,
            detail: "rewrote arg1 from 0 to 1 (keeping process dumpable)".into(),
        });
    }

    /// Record an INT3 skip event.
    pub fn record_int3_skip(&mut self, addr: VirtAddr, event_log: &mut EventLog) {
        self.stats.int3_skipped += 1;
        event_log.record(EventKind::AntiDebugDetected {
            technique: "INT3 self-check".into(),
            addr: Some(addr),
            bypassed: true,
            detail: format!("auto-skipped INT3 trap at {}", addr),
        });
    }

    /// Check if INT3 auto-skip is enabled.
    pub fn should_skip_int3(&self) -> bool {
        self.config.skip_int3_traps
    }

    /// Spoof TracerPid in a buffer read from /proc/self/status.
    ///
    /// Replaces `TracerPid:\t<nonzero>` with `TracerPid:\t0` in the given
    /// buffer. Returns the modified buffer.
    pub fn spoof_tracer_pid(buf: &[u8]) -> Vec<u8> {
        let mut result = buf.to_vec();
        let needle = b"TracerPid:\t";

        if let Some(pos) = buf
            .windows(needle.len())
            .position(|w| w == needle)
        {
            let value_start = pos + needle.len();
            // Find end of the number (next newline or end of buffer)
            let value_end = result[value_start..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| value_start + p)
                .unwrap_or(result.len());

            // Replace the PID digits with "0" + padding spaces to keep length
            let old_len = value_end - value_start;
            if old_len > 0 {
                result[value_start] = b'0';
                for byte in &mut result[value_start + 1..value_end] {
                    *byte = b' ';
                }
            }
        }

        result
    }
}

/// Check if a signal number is commonly used for anti-debug self-signaling.
fn is_anti_debug_signal(sig: u64) -> bool {
    matches!(
        sig,
        SIGALRM   // Watchdog timer expiry
        | SIGTERM  // Self-termination
        | 6       // SIGABRT
        | 9       // SIGKILL (won't reach handler, but suppressing the syscall works)
        | 10      // SIGUSR1 (often used as anti-debug signal)
        | 12      // SIGUSR2
        | 19      // SIGSTOP (attempt to freeze self)
    )
}

/// Get the signal name for a signal number.
fn signal_name(sig: u64) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGCHLD => "SIGCHLD",
        19 => "SIGSTOP",
        _ => "SIG??",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> BypassEngine {
        BypassEngine::all_enabled()
    }

    fn no_read(_addr: u64) -> Option<String> {
        None
    }

    #[test]
    fn bypass_ptrace_traceme() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // Syscall entry: ptrace(PTRACE_TRACEME, 0, 0, 0)
        let args = [PTRACE_TRACEME, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_PTRACE, &args, &no_read);
        assert_eq!(action, BypassAction::None); // No entry action

        // Syscall exit: return -1 (would fail without bypass)
        let action = engine.on_syscall_exit(SYS_PTRACE, -1, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
        assert_eq!(engine.stats().ptrace_bypassed, 1);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn bypass_prctl_dumpable() {
        let mut engine = make_engine();

        // prctl(PR_SET_DUMPABLE, 0, ...)
        let args = [PR_SET_DUMPABLE, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_PRCTL, &args, &no_read);
        assert_eq!(
            action,
            BypassAction::RewriteArg {
                arg_index: 1,
                new_value: 1,
            }
        );
    }

    #[test]
    fn bypass_proc_status_tracking() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // openat(AT_FDCWD, "/proc/self/status", O_RDONLY)
        let read_string = |_addr: u64| -> Option<String> {
            Some("/proc/self/status".into())
        };
        let args = [0xffffff9c_u64, 0x7fff0000, 0, 0, 0, 0]; // AT_FDCWD, path, flags
        let action = engine.on_syscall_entry(SYS_OPENAT, &args, &read_string);
        assert_eq!(action, BypassAction::None);

        // openat returns fd=5
        let action = engine.on_syscall_exit(SYS_OPENAT, 5, &mut log);
        assert_eq!(action, BypassAction::None); // Just tracking
        assert!(engine.proc_status_fds.contains(&5));

        // read(5, buf, count)
        let args = [5, 0x7fff1000, 4096, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_READ, &args, &no_read);
        assert_eq!(action, BypassAction::None);

        // read returns 200 bytes
        let action = engine.on_syscall_exit(SYS_READ, 200, &mut log);
        assert_eq!(action, BypassAction::SpoofTracerPid);
        assert_eq!(engine.stats().proc_status_spoofed, 1);

        // close(5) should stop tracking
        let args = [5, 0, 0, 0, 0, 0];
        engine.on_syscall_entry(SYS_CLOSE, &args, &no_read);
        assert!(!engine.proc_status_fds.contains(&5));
    }

    #[test]
    fn spoof_tracer_pid_buffer() {
        let input = b"Name:\ttest\nTracerPid:\t12345\nUid:\t1000\n";
        let result = BypassEngine::spoof_tracer_pid(input);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("TracerPid:\t0"));
        assert!(!text.contains("12345"));
        // Length preserved
        assert_eq!(result.len(), input.len());
    }

    #[test]
    fn spoof_tracer_pid_already_zero() {
        let input = b"TracerPid:\t0\n";
        let result = BypassEngine::spoof_tracer_pid(input);
        assert_eq!(&result, input);
    }

    #[test]
    fn no_bypass_when_disabled() {
        let config = BypassEngineConfig {
            bypass_ptrace: false,
            bypass_proc_status: false,
            bypass_prctl_dumpable: false,
            skip_int3_traps: false,
            patch_rdtsc: false,
            neutralize_watchdog_timers: false,
            suppress_self_signals: false,
            log_signal_handlers: false,
        };
        let mut engine = BypassEngine::new(config);
        let mut log = EventLog::new();

        // ptrace(TRACEME) should not be intercepted
        let args = [PTRACE_TRACEME, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_PTRACE, &args, &no_read);
        assert_eq!(action, BypassAction::None);
        let action = engine.on_syscall_exit(SYS_PTRACE, -1, &mut log);
        assert_eq!(action, BypassAction::None);
        assert_eq!(engine.stats().ptrace_bypassed, 0);
        assert!(log.is_empty());
    }

    #[test]
    fn default_config_enables_key_bypasses() {
        let config = BypassEngineConfig::default();
        assert!(config.bypass_ptrace);
        assert!(config.bypass_proc_status);
        assert!(config.bypass_prctl_dumpable);
        assert!(config.skip_int3_traps);
        assert!(!config.patch_rdtsc); // Off by default
        assert!(config.neutralize_watchdog_timers);
        assert!(config.suppress_self_signals);
        assert!(config.log_signal_handlers);
    }

    #[test]
    fn unrelated_syscall_no_action() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // write(1, buf, 13) — completely unrelated
        let args = [1, 0x7fff0000, 13, 0, 0, 0];
        let action = engine.on_syscall_entry(1, &args, &no_read);
        assert_eq!(action, BypassAction::None);
        let action = engine.on_syscall_exit(1, 13, &mut log);
        assert_eq!(action, BypassAction::None);
        assert!(log.is_empty());
    }

    #[test]
    fn ptrace_non_traceme_not_bypassed() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // ptrace(PTRACE_PEEKDATA, ...) — not TRACEME
        let args = [2, 1234, 0x7fff0000, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_PTRACE, &args, &no_read);
        assert_eq!(action, BypassAction::None);
        let action = engine.on_syscall_exit(SYS_PTRACE, 42, &mut log);
        assert_eq!(action, BypassAction::None);
    }

    #[test]
    fn int3_skip_check() {
        let engine = make_engine();
        assert!(engine.should_skip_int3());

        let disabled = BypassEngine::new(BypassEngineConfig {
            skip_int3_traps: false,
            ..Default::default()
        });
        assert!(!disabled.should_skip_int3());
    }

    #[test]
    fn stats_tracking() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // Two ptrace bypasses
        for _ in 0..2 {
            let args = [PTRACE_TRACEME, 0, 0, 0, 0, 0];
            engine.on_syscall_entry(SYS_PTRACE, &args, &no_read);
            engine.on_syscall_exit(SYS_PTRACE, -1, &mut log);
        }

        // One INT3 skip
        engine.record_int3_skip(VirtAddr(0x401000), &mut log);

        // One prctl rewrite
        engine.record_prctl_bypass(&mut log);

        let stats = engine.stats();
        assert_eq!(stats.ptrace_bypassed, 2);
        assert_eq!(stats.int3_skipped, 1);
        assert_eq!(stats.prctl_rewritten, 1);
    }

    // ── Signal-based anti-analysis tests (Mirai-style) ──

    #[test]
    fn bypass_alarm_watchdog() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // alarm(30) — 30 second watchdog timer
        let args = [30, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_ALARM, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        // On exit, should fake return value 0 (no previous alarm)
        let action = engine.on_syscall_exit(SYS_ALARM, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
        assert_eq!(engine.stats().timers_neutralized, 1);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn bypass_setitimer_watchdog() {
        let mut engine = make_engine();
        let mut log = EventLog::new();

        // setitimer(ITIMER_REAL=0, new_value, old_value)
        let args = [0, 0x7fff0000, 0x7fff1000, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_SETITIMER, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        let action = engine.on_syscall_exit(SYS_SETITIMER, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
        assert_eq!(engine.stats().timers_neutralized, 1);
    }

    #[test]
    fn setitimer_non_real_not_bypassed() {
        let mut engine = make_engine();

        // setitimer(ITIMER_VIRTUAL=1, ...) — not a SIGALRM timer
        let args = [1, 0x7fff0000, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_SETITIMER, &args, &no_read);
        assert_eq!(action, BypassAction::None);
    }

    #[test]
    fn alarm_zero_not_bypassed() {
        let mut engine = make_engine();

        // alarm(0) — cancel existing alarm, should pass through
        let args = [0, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_ALARM, &args, &no_read);
        assert_eq!(action, BypassAction::None);
    }

    #[test]
    fn bypass_self_signal_kill() {
        let mut engine = make_engine();
        engine.set_tracee_ids(1234, 1234);
        let mut log = EventLog::new();

        // kill(getpid()=1234, SIGALRM=14)
        let args = [1234, 14, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_KILL, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        let action = engine.on_syscall_exit(SYS_KILL, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
        assert_eq!(engine.stats().self_signals_suppressed, 1);
    }

    #[test]
    fn bypass_self_signal_kill_pid_zero() {
        let mut engine = make_engine();
        engine.set_tracee_ids(5678, 5678);
        let mut log = EventLog::new();

        // kill(0, SIGTERM=15) — pid=0 means "own process group"
        let args = [0, 15, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_KILL, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        let action = engine.on_syscall_exit(SYS_KILL, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
    }

    #[test]
    fn kill_other_process_not_bypassed() {
        let mut engine = make_engine();
        engine.set_tracee_ids(1234, 1234);

        // kill(9999, SIGTERM) — sending to different process
        let args = [9999, 15, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_KILL, &args, &no_read);
        assert_eq!(action, BypassAction::None);
    }

    #[test]
    fn kill_non_antidebug_signal_not_bypassed() {
        let mut engine = make_engine();
        engine.set_tracee_ids(1234, 1234);

        // kill(1234, SIGCHLD=17) — SIGCHLD is not an anti-debug signal
        let args = [1234, 17, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_KILL, &args, &no_read);
        assert_eq!(action, BypassAction::None);
    }

    #[test]
    fn bypass_tgkill_self_signal() {
        let mut engine = make_engine();
        engine.set_tracee_ids(1234, 1234);
        let mut log = EventLog::new();

        // tgkill(1234, 1234, SIGTERM=15)
        let args = [1234, 1234, 15, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_TGKILL, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        let action = engine.on_syscall_exit(SYS_TGKILL, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
        assert_eq!(engine.stats().self_signals_suppressed, 1);
    }

    #[test]
    fn bypass_tkill_self_signal() {
        let mut engine = make_engine();
        engine.set_tracee_ids(1234, 1234);
        let mut log = EventLog::new();

        // tkill(1234, SIGABRT=6)
        let args = [1234, 6, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_TKILL, &args, &no_read);
        assert_eq!(action, BypassAction::SkipSyscall);

        let action = engine.on_syscall_exit(SYS_TKILL, 0, &mut log);
        assert_eq!(action, BypassAction::FakeReturnValue(0));
    }

    #[test]
    fn rt_sigaction_logged() {
        let mut engine = make_engine();

        // rt_sigaction(SIGALRM=14, act=0x7fff, oldact=NULL, sigsetsize=8)
        let args = [14, 0x7fff0000, 0, 8, 0, 0];
        let action = engine.on_syscall_entry(SYS_RT_SIGACTION, &args, &no_read);
        assert_eq!(action, BypassAction::None); // Don't block, just log
        assert_eq!(engine.stats().signal_handlers_logged, 1);
    }

    #[test]
    fn rt_sigaction_null_act_not_logged() {
        let mut engine = make_engine();

        // rt_sigaction(SIGALRM, NULL, oldact, 8) — just querying
        let args = [14, 0, 0x7fff0000, 8, 0, 0];
        engine.on_syscall_entry(SYS_RT_SIGACTION, &args, &no_read);
        assert_eq!(engine.stats().signal_handlers_logged, 0);
    }

    #[test]
    fn signal_policy_management() {
        let mut engine = make_engine();

        assert_eq!(engine.signal_policy(14), SignalBypassPolicy::Default);

        engine.set_signal_policy(14, SignalBypassPolicy::TransparentPass);
        assert_eq!(engine.signal_policy(14), SignalBypassPolicy::TransparentPass);

        engine.set_signal_policy(14, SignalBypassPolicy::Suppress);
        assert_eq!(engine.signal_policy(14), SignalBypassPolicy::Suppress);
    }

    #[test]
    fn is_anti_debug_signal_classification() {
        assert!(is_anti_debug_signal(14)); // SIGALRM
        assert!(is_anti_debug_signal(15)); // SIGTERM
        assert!(is_anti_debug_signal(6));  // SIGABRT
        assert!(is_anti_debug_signal(9));  // SIGKILL
        assert!(is_anti_debug_signal(10)); // SIGUSR1
        assert!(is_anti_debug_signal(12)); // SIGUSR2

        assert!(!is_anti_debug_signal(17)); // SIGCHLD — not anti-debug
        assert!(!is_anti_debug_signal(11)); // SIGSEGV — real crash
        assert!(!is_anti_debug_signal(2));  // SIGINT — user interrupt
    }

    #[test]
    fn signal_disabled_no_bypass() {
        let config = BypassEngineConfig {
            suppress_self_signals: false,
            neutralize_watchdog_timers: false,
            ..Default::default()
        };
        let mut engine = BypassEngine::new(config);
        engine.set_tracee_ids(1234, 1234);

        // kill(self, SIGALRM) should not be intercepted
        let args = [1234, 14, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_KILL, &args, &no_read);
        assert_eq!(action, BypassAction::None);

        // alarm() should not be intercepted
        let args = [30, 0, 0, 0, 0, 0];
        let action = engine.on_syscall_entry(SYS_ALARM, &args, &no_read);
        assert_eq!(action, BypassAction::None);
    }
}
