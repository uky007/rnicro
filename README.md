# rnicro

[![Crates.io](https://img.shields.io/crates/v/rnicro.svg)](https://crates.io/crates/rnicro)
[![docs.rs](https://docs.rs/rnicro/badge.svg)](https://docs.rs/rnicro)
[![License: MIT](https://img.shields.io/crates/l/rnicro.svg)](LICENSE)

A Linux x86\_64 debugger and exploit development toolkit written in Rust, specialized for Rust binary analysis and security research.

## Features

**Core Debugger** — ptrace-based process control, software/hardware breakpoints, watchpoints, multi-thread support, source-level stepping, DWARF variables with Rust type pretty-printing.

**Exploit Development** — ROP gadget search and chain builder, format string payloads, heap analysis (glibc), shellcode toolkit, SROP, one-gadget finder, ASLR leak calculator.

**Automation** — Structured event logging, anti-analysis bypass engine (ptrace, /proc spoofing, signal-based tricks like Mirai), and memory secret extraction (differential strings, entropy detection, known patterns).

**Editor Integration** — Debug Adapter Protocol (DAP) server with VS Code extension. Security analysis panel, Rust-specialized variable display.

## Quick Start

```bash
cargo install rnicro

# CLI debugger (Linux only — ptrace)
rnicro ./target/debug/my_program

# Emulator mode (any platform — static ELF / shellcode)
rnicro --emulate ./static_binary

# DAP mode (for editors, Linux only)
rnicro --dap
```

## Module Overview

| Category | Modules |
|----------|---------|
| Core | `process`, `registers`, `breakpoint`, `watchpoint`, `target` |
| Debug Info | `elf`, `dwarf`, `variables`, `rust_type`, `unwind`, `disasm` |
| Recon | `checksec`, `strings`, `entropy`, `antidebug`, `memscan`, `syscall_trace` |
| Exploit | `rop`, `rop_chain`, `one_gadget`, `sigrop`, `fmtstr`, `shellcode`, `heap`, `heap_exploit` |
| Automation | `event_log`, `antianalysis`, `secret_scan`, `emulator` |
| Integration | `dap_server`, `gdb_rsp`, `tube` |

## Anti-Analysis Bypass

The bypass engine automatically neutralizes common anti-debugging techniques at runtime:

- `ptrace(TRACEME)` self-trace — fakes success
- `/proc/self/status` TracerPid — spoofs to 0
- `prctl(PR_SET_DUMPABLE, 0)` — rewrites arg to keep dumpable
- `alarm()` / `setitimer()` watchdog timers — neutralized
- `kill(getpid(), sig)` / `tgkill` self-signals — suppressed
- INT3 self-check traps — auto-skipped

## Secret Extraction

Automatically scans writable memory on sensitive syscalls (write, sendto) using:

- **Differential scanning** — detects newly appeared printable strings
- **Entropy tracking** — identifies decryption events (high-to-low entropy transitions)
- **Pattern matching** — AWS keys, JWT, PEM, GitHub tokens, Bearer tokens

## Platform

- **Debugger (ptrace)**: Linux x86\_64 only
- **Emulator**: Any platform (macOS, Linux) — static ELF and shellcode only; dynamic binaries (glibc, shared libs) require ptrace mode
- **Development**: macOS compatible (Linux-only modules behind `#[cfg(target_os = "linux")]`)

## License

MIT
