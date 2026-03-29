# rnicro Debugger for VS Code

Debug adapter extension for [rnicro](https://github.com/uky007/rnicro), a Linux x86_64 debugger and exploit development toolkit written in Rust.

## Prerequisites

- Linux x86_64 system (rnicro uses ptrace)
- rnicro binary installed and available in `$PATH` (or configure `rnicro.path`)

```sh
cargo install rnicro
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

## Debug Console Queries

Type these expressions in the Debug Console while a session is active:

| Expression | Result |
|------------|--------|
| `$events` | Last 20 events from the structured event log |
| `$bypass` | Anti-analysis bypass engine status and counters |
| `$secrets` | All secrets discovered in memory so far |

Anti-debug bypasses and secret findings are also shown automatically as output events in the Debug Console whenever they occur.

## Supported Features

| Feature                    | Status |
|----------------------------|--------|
| Source breakpoints         | Yes    |
| Conditional breakpoints    | Yes    |
| Function breakpoints       | Yes    |
| Exception breakpoints      | Yes (signals: all, SIGSEGV, SIGABRT) |
| Data breakpoints           | Yes (hardware watchpoints) |
| Instruction breakpoints    | Yes (breakpoint by address) |
| Deferred breakpoints       | Yes (set before launch, applied on configurationDone) |
| Step over / into / out     | Yes    |
| Continue / Pause           | Yes    |
| Stack traces               | Yes    |
| Local variables            | Yes (Rust type pretty-printing) |
| Register view              | Yes    |
| Hover evaluation           | Yes    |
| Disassembly view           | Yes    |
| Memory read / write        | Yes    |
| Multi-thread support       | Yes    |
| Security analysis          | Yes (checksec + antidebug on launch) |
| Anti-analysis bypass       | Yes (automatic, real-time notifications) |
| Secret extraction          | Yes (automatic, real-time notifications) |

## Limitations

- Linux x86_64 only (ptrace-based debugger)
- Dynamic ELF analysis only (static binaries use `--emulate` mode from CLI)
