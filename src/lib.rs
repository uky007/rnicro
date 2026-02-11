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
//! - [`process`] — Process control via ptrace (launch, attach, continue, step).
//! - [`registers`] — x86_64 register read/write with a table-driven design.
//! - [`breakpoint`] — Software breakpoint management (INT3 patching).
//! - [`target`] — High-level debugger API integrating all components.

pub mod error;
pub mod types;
pub mod process;
pub mod registers;
pub mod breakpoint;
pub mod target;
