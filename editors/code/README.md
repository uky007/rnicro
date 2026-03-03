# rnicro Debugger for VS Code

Debug adapter extension for [rnicro](https://github.com/rnicro/rnicro), a Linux x86_64 debugger and exploit development toolkit written in Rust.

## Prerequisites

- Linux x86_64 system (rnicro uses ptrace)
- rnicro binary installed and available in `$PATH` (or configure `rnicro.path`)

```sh
# Build from source
cargo build --release
# Binary at target/release/rnicro
```

## Installation

Install from `.vsix` file:

```sh
code --install-extension rnicro-0.1.0.vsix
```

## Usage

### Launch Configuration

Create `.vscode/launch.json` in your project:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "rnicro",
      "request": "launch",
      "name": "rnicro: Launch",
      "program": "${workspaceFolder}/target/debug/myapp",
      "args": [],
      "stopOnEntry": true
    }
  ]
}
```

### Attach to Process

```json
{
  "type": "rnicro",
  "request": "attach",
  "name": "rnicro: Attach",
  "pid": "${command:rnicro.pickProcess}"
}
```

## Settings

| Setting       | Default    | Description                          |
|---------------|------------|--------------------------------------|
| `rnicro.path` | `"rnicro"` | Path to the rnicro binary (or PATH lookup) |

## Supported Features

| Feature                  | Status |
|--------------------------|--------|
| Source breakpoints       | Yes    |
| Conditional breakpoints  | Yes    |
| Function breakpoints     | Yes    |
| Exception breakpoints    | Yes (signals: all, SIGSEGV, SIGABRT) |
| Step over / into / out   | Yes    |
| Continue / Pause         | Yes    |
| Stack traces             | Yes    |
| Local variables          | Yes    |
| Register view            | Yes    |
| Hover evaluation         | Yes    |
| Disassembly view         | Yes    |
| Memory read              | Yes    |

## Limitations

- Linux x86_64 only (ptrace-based debugger)
- Single-thread stepping (multi-thread support planned)
- Data breakpoints (watchpoints) declared but handler not yet wired
