//! rnicro — A Linux x86_64 debugger and exploit development toolkit written in Rust.
//!
//! Based on the architecture of [sdb](https://github.com/TartanLlama/sdb),
//! the reference implementation for the book
//! ["Building a Debugger"](https://nostarch.com/building-a-debugger) by Sy Brand.
//! Extended with offensive security tooling for binary exploitation,
//! reverse engineering, and vulnerability research.
//!
//! # Module overview
//!
//! ## Core debugger
//!
//! - [`error`] — Error types used throughout the crate.
//! - [`types`] — Core types: `VirtAddr`, `StopReason`, `ProcessState`.
//! - [`pipe`] — Fork/exec synchronization pipe.
//! - [`procfs`] — Linux procfs utilities (`/proc/pid/maps`, etc.).
//! - [`process`] — Process control via ptrace (launch, attach, continue, step). *(Linux-only)*
//! - [`registers`] — x86_64 register read/write with a table-driven design. *(Linux-only)*
//! - [`breakpoint`] — Software breakpoint management (INT3 patching). *(Linux-only)*
//! - [`watchpoint`] — Hardware watchpoint management via debug registers. *(Linux-only)*
//! - [`target`] — High-level debugger API integrating all components. *(Linux-only)*
//!
//! ## Debug information
//!
//! - [`elf`] — ELF binary loading and symbol resolution.
//! - [`dwarf`] — DWARF debug info parsing (line tables, function names).
//! - [`dwarf_expr`] — DWARF expression evaluator (location expressions).
//! - [`expr_eval`] — Simple C expression parser and evaluator.
//! - [`variables`] — Variable and type inspection via DWARF.
//! - [`unwind`] — Stack unwinding via DWARF Call Frame Information (CFI).
//! - [`disasm`] — x86_64 disassembly using iced-x86.
//!
//! ## Offensive security — Reconnaissance
//!
//! - [`checksec`] — Security mechanism analysis (RELRO, NX, PIE, canary, FORTIFY).
//! - [`strings`] — String extraction from ELF binaries.
//! - [`entropy`] — Per-section Shannon entropy analysis.
//! - [`antidebug`] — Anti-debugging detection and bypass.
//! - [`memscan`] — Memory scanning with IDA-style wildcard patterns.
//! - [`syscall`] — Linux x86_64 syscall name/number mapping.
//! - [`syscall_trace`] — Enhanced syscall tracing with argument decoding.
//!
//! ## Offensive security — Exploit development
//!
//! - [`rop`] — ROP gadget search in ELF segments.
//! - [`rop_chain`] — Automated ROP chain builder with BFS register assignment.
//! - [`one_gadget`] — One-gadget / magic gadget finder for libc.
//! - [`sigrop`] — Sigreturn-Oriented Programming (SROP) chain builder.
//! - [`fmtstr`] — Format string exploit payload generation.
//! - [`shellcode`] — Shellcode analysis and transformation toolkit.
//! - [`pattern`] — De Bruijn cyclic pattern for buffer overflow offset detection.
//! - [`aslr`] — ASLR/PIE leak calculator and libc offset database.
//! - [`heap`] — glibc heap structure parsing (malloc_chunk, tcache, arenas).
//! - [`heap_exploit`] — Heap exploit primitives (tcache poison, fastbin dup, House of Force).
//!
//! ## Offensive security — Runtime analysis
//!
//! - [`patch`] — Binary patching (on-disk ELF and live memory).
//! - [`got_hook`] — GOT/PLT function hooking for call interception.
//! - [`coredump`] — ELF core dump generation from a stopped process.
//! - [`shared_lib`] — Shared library tracking via `r_debug` / `link_map`. *(Linux-only)*
//!
//! ## Integration
//!
//! - [`gdb_rsp`] — GDB Remote Serial Protocol server for external tool integration.
//! - [`tube`] — Process I/O tubes for automated exploit delivery (pwntools-style).

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
pub mod fmtstr;
pub mod memscan;
pub mod got_hook;
pub mod shellcode;
pub mod sigrop;
pub mod aslr;
pub mod heap_exploit;
pub mod rop_chain;
pub mod one_gadget;
pub mod tube;

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
