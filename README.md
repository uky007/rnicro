# rnicro

[![Crates.io](https://img.shields.io/crates/v/rnicro.svg)](https://crates.io/crates/rnicro)
[![docs.rs](https://docs.rs/rnicro/badge.svg)](https://docs.rs/rnicro)
[![CI](https://github.com/uky007/rnicro/actions/workflows/ci.yml/badge.svg)](https://github.com/uky007/rnicro/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/crates/l/rnicro.svg)](LICENSE)

A Linux x86\_64 debugger and exploit development toolkit written in Rust, specialized for Rust binary analysis and security research.

## Features

**Core Debugger** — ptrace-based process control, software/hardware breakpoints, watchpoints, multi-thread support, source-level stepping, DWARF variables with Rust type pretty-printing.

**Exploit Development** — ROP gadget search and chain builder, format string payloads, heap analysis (glibc), shellcode toolkit, SROP, one-gadget finder, ASLR leak calculator.

**Automation** — Structured event logging, anti-analysis bypass engine (ptrace, /proc spoofing, Mirai-style signal tricks), and memory secret extraction (differential strings, entropy detection, known patterns).

**Emulator** — x86\_64 CPU emulator via unicorn-engine for offline analysis of static ELF binaries and shellcode. Works on macOS and Linux.

**Editor Integration** — DAP server with VS Code extension. Security analysis panel, Rust-specialized variable display, real-time bypass/secret notifications in the debug console.

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

## CLI Commands

### Debugger REPL (Linux)

50+ commands including `continue`, `break`, `step`, `memory`, `disas`, `strace`, `checksec`, `rop`, `heap`, plus:

| Command | Description |
|---------|-------------|
| `events [N\|syscalls\|export\|clear]` | View/filter/export the structured event log |
| `bypass [on\|off]` | Show anti-analysis bypass status and stats, toggle engine |
| `secrets [scan]` | Show discovered secrets or trigger a manual memory scan |

### Emulator Mode

```bash
rnicro --emulate ./binary      # Run and show summary
RNICRO_JSON=1 rnicro --emulate ./binary  # Include full JSON event log
```

### DAP Debug Console

Type these in the VS Code / editor debug console while debugging:

| Expression | Result |
|------------|--------|
| `$events` | Last 20 events from the session log |
| `$bypass` | Anti-analysis bypass engine status and counters |
| `$secrets` | All secrets discovered in memory |

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

The bypass engine automatically neutralizes common anti-debugging techniques at runtime (both ptrace and emulator modes):

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

Previews are masked (first/last 4 chars only) to prevent the debugger itself from becoming a leakage surface.

## Platform

- **Debugger (ptrace)**: Linux x86\_64 only
- **Emulator**: Any platform (macOS, Linux) — static ELF and shellcode only; dynamic binaries require ptrace mode
- **CI**: Linux (fmt, clippy, build, test) + macOS (build, test)

## License

MIT
