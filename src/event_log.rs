//! Structured event logging for automated debugging.
//!
//! Records all significant events during a debug session: syscalls,
//! signals, breakpoints, anti-analysis bypass actions, and secret
//! discoveries. Provides filtering and query APIs for analysis.

use std::collections::HashSet;
use std::time::{Instant, Duration};

use crate::types::VirtAddr;

/// Category of a debug event for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCategory {
    Syscall,
    Signal,
    Breakpoint,
    AntiDebug,
    Secret,
}

/// A single debug event recorded during execution.
#[derive(Debug, Clone)]
pub struct DebugEvent {
    /// Monotonic sequence number (0-based).
    pub seq: u64,
    /// Time elapsed since session start.
    pub elapsed: Duration,
    /// Event payload.
    pub kind: EventKind,
}

/// The payload of a debug event.
#[derive(Debug, Clone)]
pub enum EventKind {
    /// A syscall was entered.
    SyscallEntry {
        number: u64,
        name: String,
        args_formatted: String,
    },
    /// A syscall returned.
    SyscallExit {
        number: u64,
        name: String,
        retval: i64,
        retval_formatted: String,
    },
    /// A signal was received by the tracee.
    Signal {
        signal: String,
        addr: Option<VirtAddr>,
    },
    /// A breakpoint was hit.
    BreakpointHit {
        addr: VirtAddr,
        function: Option<String>,
        location: Option<String>,
    },
    /// An anti-analysis technique was detected (and optionally bypassed).
    AntiDebugDetected {
        technique: String,
        addr: Option<VirtAddr>,
        bypassed: bool,
        detail: String,
    },
    /// A secret or sensitive value was found in memory.
    SecretFound {
        addr: VirtAddr,
        category: SecretCategory,
        preview: String,
        size: usize,
    },
    /// Process exited.
    ProcessExited {
        code: i32,
    },
    /// Process terminated by signal.
    ProcessTerminated {
        signal: String,
    },
    /// Thread created.
    ThreadCreated {
        tid: i32,
    },
    /// Thread exited.
    ThreadExited {
        tid: i32,
    },
}

/// Classification of discovered secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretCategory {
    /// Newly appeared printable string (differential detection).
    NewString,
    /// High-entropy blob (potential crypto key or encrypted data).
    HighEntropy,
    /// Matches a known pattern (API key, token, etc.).
    KnownPattern,
    /// Decrypted data (entropy decreased in a previously high-entropy region).
    Decrypted,
}

impl std::fmt::Display for SecretCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewString => write!(f, "new_string"),
            Self::HighEntropy => write!(f, "high_entropy"),
            Self::KnownPattern => write!(f, "known_pattern"),
            Self::Decrypted => write!(f, "decrypted"),
        }
    }
}

impl EventKind {
    /// Return the category of this event.
    pub fn category(&self) -> EventCategory {
        match self {
            Self::SyscallEntry { .. } | Self::SyscallExit { .. } => EventCategory::Syscall,
            Self::Signal { .. }
            | Self::ProcessExited { .. }
            | Self::ProcessTerminated { .. }
            | Self::ThreadCreated { .. }
            | Self::ThreadExited { .. } => EventCategory::Signal,
            Self::BreakpointHit { .. } => EventCategory::Breakpoint,
            Self::AntiDebugDetected { .. } => EventCategory::AntiDebug,
            Self::SecretFound { .. } => EventCategory::Secret,
        }
    }

    /// Format this event as a one-line log string.
    pub fn format_oneline(&self) -> String {
        match self {
            Self::SyscallEntry { name, args_formatted, .. } => {
                format!("syscall {} {}", name, args_formatted)
            }
            Self::SyscallExit { name, retval_formatted, .. } => {
                format!("syscall {} = {}", name, retval_formatted)
            }
            Self::Signal { signal, addr } => {
                if let Some(a) = addr {
                    format!("signal {} at {}", signal, a)
                } else {
                    format!("signal {}", signal)
                }
            }
            Self::BreakpointHit { addr, function, location } => {
                let func = function.as_deref().unwrap_or("??");
                let loc = location.as_deref().unwrap_or("");
                format!("breakpoint {} {} {}", addr, func, loc)
            }
            Self::AntiDebugDetected { technique, bypassed, detail, .. } => {
                let action = if *bypassed { "BYPASSED" } else { "DETECTED" };
                format!("antidebug [{}] {} — {}", action, technique, detail)
            }
            Self::SecretFound { addr, category, preview, size } => {
                format!("secret [{}] {} bytes at {} — {}", category, size, addr, preview)
            }
            Self::ProcessExited { code } => format!("process exited ({})", code),
            Self::ProcessTerminated { signal } => format!("process terminated ({})", signal),
            Self::ThreadCreated { tid } => format!("thread created ({})", tid),
            Self::ThreadExited { tid } => format!("thread exited ({})", tid),
        }
    }
}

/// Configuration for the event logger.
#[derive(Debug, Clone)]
pub struct EventLogConfig {
    /// Which categories to record (empty = all).
    pub categories: HashSet<EventCategory>,
    /// Maximum number of events to keep (0 = unlimited).
    pub max_events: usize,
    /// Syscall numbers to exclude from logging (noisy ones like clock_gettime).
    pub excluded_syscalls: HashSet<u64>,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            categories: HashSet::new(), // empty = log everything
            max_events: 100_000,        // prevent unbounded growth
            excluded_syscalls: HashSet::new(),
        }
    }
}

/// Persistent event log for a debug session.
#[derive(Debug)]
pub struct EventLog {
    events: Vec<DebugEvent>,
    next_seq: u64,
    start_time: Instant,
    config: EventLogConfig,
}

impl EventLog {
    /// Create a new event log.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            next_seq: 0,
            start_time: Instant::now(),
            config: EventLogConfig::default(),
        }
    }

    /// Create a new event log with configuration.
    pub fn with_config(config: EventLogConfig) -> Self {
        Self {
            events: Vec::new(),
            next_seq: 0,
            start_time: Instant::now(),
            config,
        }
    }

    /// Record an event. Returns the sequence number, or `None` if filtered out.
    pub fn record(&mut self, kind: EventKind) -> Option<u64> {
        // Category filter
        if !self.config.categories.is_empty()
            && !self.config.categories.contains(&kind.category())
        {
            return None;
        }

        // Syscall exclusion filter
        match &kind {
            EventKind::SyscallEntry { number, .. }
            | EventKind::SyscallExit { number, .. } => {
                if self.config.excluded_syscalls.contains(number) {
                    return None;
                }
            }
            _ => {}
        }

        let seq = self.next_seq;
        self.next_seq += 1;

        let event = DebugEvent {
            seq,
            elapsed: self.start_time.elapsed(),
            kind,
        };

        self.events.push(event);

        // Evict oldest if over limit
        if self.config.max_events > 0 && self.events.len() > self.config.max_events {
            self.events.remove(0);
        }

        Some(seq)
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[DebugEvent] {
        &self.events
    }

    /// Get events filtered by category.
    pub fn events_by_category(&self, category: EventCategory) -> Vec<&DebugEvent> {
        self.events
            .iter()
            .filter(|e| e.kind.category() == category)
            .collect()
    }

    /// Get the last N events.
    pub fn last_n(&self, n: usize) -> &[DebugEvent] {
        let start = self.events.len().saturating_sub(n);
        &self.events[start..]
    }

    /// Total number of events recorded.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Get the configuration (mutable for runtime changes).
    pub fn config_mut(&mut self) -> &mut EventLogConfig {
        &mut self.config
    }

    /// Format all events as a multi-line log.
    pub fn format_log(&self) -> String {
        self.events
            .iter()
            .map(|e| {
                format!(
                    "[{:>6}] {:>10.3}s  {}",
                    e.seq,
                    e.elapsed.as_secs_f64(),
                    e.kind.format_oneline()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export events as a JSON array string.
    ///
    /// Uses serde_json for correct escaping of all special characters
    /// (newlines, quotes, backslashes, control chars, etc.).
    pub fn export_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "seq": e.seq,
                    "elapsed_ms": e.elapsed.as_millis() as u64,
                    "event": e.kind.format_oneline(),
                })
            })
            .collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query_events() {
        let mut log = EventLog::new();

        log.record(EventKind::SyscallEntry {
            number: 1,
            name: "write".into(),
            args_formatted: "(fd=1<stdout>, buf=0x7fff, count=13)".into(),
        });
        log.record(EventKind::SyscallExit {
            number: 1,
            name: "write".into(),
            retval: 13,
            retval_formatted: "13".into(),
        });
        log.record(EventKind::Signal {
            signal: "SIGSEGV".into(),
            addr: Some(VirtAddr(0x401000)),
        });

        assert_eq!(log.len(), 3);
        assert_eq!(log.events_by_category(EventCategory::Syscall).len(), 2);
        assert_eq!(log.events_by_category(EventCategory::Signal).len(), 1);
    }

    #[test]
    fn category_filter() {
        let config = EventLogConfig {
            categories: [EventCategory::Syscall].into_iter().collect(),
            ..Default::default()
        };
        let mut log = EventLog::with_config(config);

        // Syscall should be recorded
        assert!(log.record(EventKind::SyscallEntry {
            number: 1,
            name: "write".into(),
            args_formatted: "()".into(),
        }).is_some());

        // Signal should be filtered out
        assert!(log.record(EventKind::Signal {
            signal: "SIGSEGV".into(),
            addr: None,
        }).is_none());

        assert_eq!(log.len(), 1);
    }

    #[test]
    fn excluded_syscalls() {
        let config = EventLogConfig {
            excluded_syscalls: [228].into_iter().collect(), // clock_gettime
            ..Default::default()
        };
        let mut log = EventLog::with_config(config);

        // clock_gettime should be excluded
        assert!(log.record(EventKind::SyscallEntry {
            number: 228,
            name: "clock_gettime".into(),
            args_formatted: "()".into(),
        }).is_none());

        // write should pass
        assert!(log.record(EventKind::SyscallEntry {
            number: 1,
            name: "write".into(),
            args_formatted: "()".into(),
        }).is_some());

        assert_eq!(log.len(), 1);
    }

    #[test]
    fn max_events_eviction() {
        let config = EventLogConfig {
            max_events: 3,
            ..Default::default()
        };
        let mut log = EventLog::with_config(config);

        for i in 0..5 {
            log.record(EventKind::SyscallEntry {
                number: i,
                name: format!("syscall_{}", i),
                args_formatted: "()".into(),
            });
        }

        assert_eq!(log.len(), 3);
        // Oldest events (seq 0, 1) should have been evicted
        assert_eq!(log.events()[0].seq, 2);
        assert_eq!(log.events()[2].seq, 4);
    }

    #[test]
    fn last_n() {
        let mut log = EventLog::new();
        for i in 0..10 {
            log.record(EventKind::ProcessExited { code: i });
        }
        let last3 = log.last_n(3);
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].seq, 7);
    }

    #[test]
    fn format_oneline() {
        let entry = EventKind::SyscallEntry {
            number: 1,
            name: "write".into(),
            args_formatted: "(fd=1<stdout>, buf=0x7fff, count=13)".into(),
        };
        let line = entry.format_oneline();
        assert!(line.contains("write"));
        assert!(line.contains("stdout"));

        let bypass = EventKind::AntiDebugDetected {
            technique: "ptrace(TRACEME)".into(),
            addr: Some(VirtAddr(0x401000)),
            bypassed: true,
            detail: "syscall 101 intercepted, returned 0".into(),
        };
        let line = bypass.format_oneline();
        assert!(line.contains("BYPASSED"));
        assert!(line.contains("ptrace"));

        let secret = EventKind::SecretFound {
            addr: VirtAddr(0x7fff0000),
            category: SecretCategory::KnownPattern,
            preview: "AKIA...".into(),
            size: 20,
        };
        let line = secret.format_oneline();
        assert!(line.contains("known_pattern"));
        assert!(line.contains("AKIA"));
    }

    #[test]
    fn secret_category_display() {
        assert_eq!(format!("{}", SecretCategory::NewString), "new_string");
        assert_eq!(format!("{}", SecretCategory::HighEntropy), "high_entropy");
        assert_eq!(format!("{}", SecretCategory::KnownPattern), "known_pattern");
        assert_eq!(format!("{}", SecretCategory::Decrypted), "decrypted");
    }

    #[test]
    fn event_category_classification() {
        assert_eq!(
            EventKind::SyscallEntry { number: 0, name: "".into(), args_formatted: "".into() }.category(),
            EventCategory::Syscall
        );
        assert_eq!(
            EventKind::Signal { signal: "".into(), addr: None }.category(),
            EventCategory::Signal
        );
        assert_eq!(
            EventKind::BreakpointHit { addr: VirtAddr(0), function: None, location: None }.category(),
            EventCategory::Breakpoint
        );
        assert_eq!(
            EventKind::AntiDebugDetected { technique: "".into(), addr: None, bypassed: false, detail: "".into() }.category(),
            EventCategory::AntiDebug
        );
        assert_eq!(
            EventKind::SecretFound { addr: VirtAddr(0), category: SecretCategory::NewString, preview: "".into(), size: 0 }.category(),
            EventCategory::Secret
        );
    }

    #[test]
    fn clear_and_empty() {
        let mut log = EventLog::new();
        assert!(log.is_empty());

        log.record(EventKind::ProcessExited { code: 0 });
        assert!(!log.is_empty());

        log.clear();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn format_log_output() {
        let mut log = EventLog::new();
        log.record(EventKind::ProcessExited { code: 42 });
        let output = log.format_log();
        assert!(output.contains("process exited (42)"));
    }

    #[test]
    fn export_json_output() {
        let mut log = EventLog::new();
        log.record(EventKind::ProcessExited { code: 0 });
        let json = log.export_json();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"seq\":0"));
        assert!(json.contains("process exited"));
    }
}
