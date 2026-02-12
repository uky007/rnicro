//! rnicro — A Linux x86_64 debugger written in Rust.
//!
//! Based on the architecture of [sdb](https://github.com/TartanLlama/sdb),
//! the reference implementation for the book
//! ["Building a Debugger"](https://nostarch.com/building-a-debugger) by Sy Brand.
//!
//! # Module overview
//!
//! - [`error`] — Error types used throughout the crate.
//! - [`types`] — Core types: `VirtAddr`, `StopReason`, `ProcessState`.
//! - [`pipe`] — Fork/exec synchronization pipe (Ch.4).
//! - [`procfs`] — Linux procfs utilities: `/proc/pid/maps`, etc. (Ch.4).
//! - [`process`] — Process control via ptrace (launch, attach, continue, step).
//! - [`registers`] — x86_64 register read/write with a table-driven design.
//! - [`breakpoint`] — Software breakpoint management (INT3 patching).
//! - [`target`] — High-level debugger API integrating all components.

// Platform-independent modules
pub mod error;
pub mod types;
pub mod pipe;
pub mod procfs;
pub mod disasm;
pub mod elf;
pub mod dwarf;
pub mod dwarf_expr;
pub mod expr_eval;
pub mod variables;
pub mod unwind;
pub mod syscall;
pub mod checksec;
pub mod strings;
pub mod rop;
pub mod entropy;
pub mod pattern;
pub mod patch;
pub mod antidebug;
pub mod heap;
pub mod coredump;
pub mod gdb_rsp;
pub mod syscall_trace;

// Linux-only modules (ptrace, user_regs_struct, etc.)
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod registers;
#[cfg(target_os = "linux")]
pub mod breakpoint;
#[cfg(target_os = "linux")]
pub mod watchpoint;
#[cfg(target_os = "linux")]
pub mod shared_lib;
#[cfg(target_os = "linux")]
pub mod target;
