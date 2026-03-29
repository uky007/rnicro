//! Debug Adapter Protocol (DAP) server for editor integration.
//!
//! Implements the [DAP specification](https://microsoft.github.io/debug-adapter-protocol/)
//! over stdin/stdout, enabling editors (VS Code, Neovim nvim-dap, Emacs dap-mode, etc.)
//! to control rnicro's debugging features through a standard protocol.
//!
//! Uses the [`dap`] crate for protocol serialization and transport.
//! Maps DAP requests to [`Target`](crate::target::Target) API calls,
//! following the same pattern as [`gdb_rsp`](crate::gdb_rsp).
//!
//! # Usage
//!
//! Launch rnicro as a DAP server:
//!
//! ```text
//! rnicro --dap
//! ```
//!
//! ## VS Code
//!
//! Install the rnicro VS Code extension from `editors/code/`.
//! The extension registers rnicro as a debug adapter and provides
//! launch.json schema validation, IntelliSense snippets, and a
//! process picker for attach mode.
//!
//! Example `.vscode/launch.json`:
//!
//! ```json
//! {
//!     "type": "rnicro",
//!     "request": "launch",
//!     "name": "rnicro: Launch",
//!     "program": "${workspaceFolder}/target/debug/myapp",
//!     "args": [],
//!     "stopOnEntry": true
//! }
//! ```
//!
//! ## Other editors
//!
//! Any editor supporting DAP can use `rnicro --dap` as a debug adapter
//! executable (stdin/stdout transport). See the DAP specification for
//! editor-specific configuration (e.g., nvim-dap, Emacs dap-mode).
//!
//! # Supported DAP commands
//!
//! | Category       | Commands                                                    |
//! |----------------|-------------------------------------------------------------|
//! | Lifecycle      | initialize, launch, attach, configurationDone, disconnect   |
//! | Breakpoints    | setBreakpoints, setFunctionBreakpoints, setExceptionBreakpoints, setDataBreakpoints, setInstructionBreakpoints |
//! | Execution      | continue, next (step over), stepIn, stepOut, pause          |
//! | Inspection     | threads, stackTrace, scopes, variables, evaluate            |
//! | Low-level      | disassemble, readMemory, writeMemory                        |
//!
//! # Architecture
//!
//! ```text
//! Editor ──stdin/stdout──► DapServer ──► Target API ──► ptrace
//!           (DAP JSON)       │              │
//!                            ├─ DwarfInfo   ├─ Process
//!                            │  (line→addr) ├─ BreakpointManager
//!                            │              ├─ Registers
//!                            └─ var_refs    └─ VariableReader
//!                               (tree)
//! ```

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use dap::events::{Event, ExitedEventBody, OutputEventBody, StoppedEventBody, ThreadEventBody};
use dap::prelude::*;
use dap::requests::Command;
use dap::responses::{Response, ResponseBody};
use dap::types::{
    Breakpoint, Capabilities, DisassembledInstruction, ExceptionBreakpointsFilter, Scope, Source,
    StackFrame, Thread,
};

use nix::unistd::Pid;

use crate::antidebug;
#[cfg(test)]
use crate::checksec::SecurityStatus;
use crate::checksec::{self, ChecksecResult};
use crate::disasm::DisasmStyle;
use crate::dwarf::DwarfInfo;
use crate::error::Result;
use crate::rust_type;
use crate::target::Target;
use crate::types::{StopReason, VirtAddr};
use crate::variables::{self, TypeKind, Variable};
use crate::watchpoint::{WatchpointSize, WatchpointType};

/// DAP server that bridges DAP protocol messages to the rnicro debugger.
pub struct DapServer<R: Read, W: Write> {
    server: Server<R, W>,
    target: Option<Target>,
    /// variablesReference -> variable list mapping.
    variable_refs: HashMap<i64, VariableScope>,
    next_var_ref: i64,
    /// Source breakpoints: (file, line) -> breakpoint address.
    source_breakpoints: HashMap<(String, i64), VirtAddr>,
    /// Breakpoint ID counter.
    next_bp_id: i64,
    /// DWARF info for source line -> address resolution (loaded before launch).
    dwarf: Option<DwarfInfo>,
    /// Data breakpoints: data_id -> watchpoint_id.
    data_breakpoints: HashMap<String, u32>,
    /// Deferred source breakpoints (set before target launch).
    deferred_source_bps: Vec<DeferredSourceBreakpoint>,
    /// Deferred function breakpoints (set before target launch).
    deferred_fn_bps: Vec<DeferredFunctionBreakpoint>,
    /// Instruction breakpoints (for replace-all semantics).
    instruction_breakpoints: Vec<VirtAddr>,
    /// Number of event log entries already sent to the editor.
    last_emitted_event: usize,
}

/// Describes the content behind a variablesReference.
enum VariableScope {
    /// Local variables at a given frame.
    Locals(i64),
    /// CPU registers.
    Registers,
    /// Children of a struct/composite variable.
    Children(Vec<(String, String, String)>), // (name, value, type)
}

/// A source breakpoint deferred until the target is launched.
struct DeferredSourceBreakpoint {
    file: String,
    line: i64,
    condition: Option<String>,
}

/// A function breakpoint deferred until the target is launched.
struct DeferredFunctionBreakpoint {
    name: String,
    condition: Option<String>,
}

impl DapServer<std::io::Stdin, std::io::Stdout> {
    /// Create a new DAP server on stdin/stdout.
    pub fn new_stdio() -> Self {
        let input = BufReader::new(std::io::stdin());
        let output = BufWriter::new(std::io::stdout());
        Self::new(input, output)
    }
}

impl<R: Read, W: Write> DapServer<R, W> {
    /// Create a new DAP server with the given I/O streams.
    pub fn new(input: BufReader<R>, output: BufWriter<W>) -> Self {
        DapServer {
            server: Server::new(input, output),
            target: None,
            variable_refs: HashMap::new(),
            next_var_ref: 1,
            source_breakpoints: HashMap::new(),
            next_bp_id: 1,
            dwarf: None,
            data_breakpoints: HashMap::new(),
            deferred_source_bps: Vec::new(),
            deferred_fn_bps: Vec::new(),
            instruction_breakpoints: Vec::new(),
            last_emitted_event: 0,
        }
    }

    /// Run the DAP server main loop.
    ///
    /// Reads DAP requests from stdin, dispatches to handlers,
    /// and sends responses/events to stdout. Exits on disconnect
    /// or I/O error.
    pub fn run(&mut self) -> Result<()> {
        loop {
            let req = match self.server.poll_request() {
                Ok(Some(req)) => req,
                Ok(None) => break,
                Err(_) => break,
            };

            let seq = req.seq;
            let result = match &req.command {
                Command::Initialize(args) => self.handle_initialize(seq, args),
                Command::Launch(args) => self.handle_launch(seq, args),
                Command::Attach(args) => self.handle_attach(seq, args),
                Command::ConfigurationDone => self.handle_configuration_done(seq),
                Command::Disconnect(_) => {
                    self.send_ok(seq, ResponseBody::Disconnect);
                    break;
                }
                Command::SetBreakpoints(args) => self.handle_set_breakpoints(seq, args),
                Command::SetFunctionBreakpoints(args) => {
                    self.handle_set_function_breakpoints(seq, args)
                }
                Command::SetExceptionBreakpoints(args) => {
                    self.handle_set_exception_breakpoints(seq, args)
                }
                Command::Continue(args) => self.handle_continue(seq, args),
                Command::Next(args) => self.handle_next(seq, args),
                Command::StepIn(args) => self.handle_step_in(seq, args),
                Command::StepOut(args) => self.handle_step_out(seq, args),
                Command::Pause(args) => self.handle_pause(seq, args),
                Command::Threads => self.handle_threads(seq),
                Command::StackTrace(args) => self.handle_stack_trace(seq, args),
                Command::Scopes(args) => self.handle_scopes(seq, args),
                Command::Variables(args) => self.handle_variables(seq, args),
                Command::Evaluate(args) => self.handle_evaluate(seq, args),
                Command::Disassemble(args) => self.handle_disassemble(seq, args),
                Command::ReadMemory(args) => self.handle_read_memory(seq, args),
                Command::WriteMemory(args) => self.handle_write_memory(seq, args),
                Command::SetDataBreakpoints(args) => self.handle_set_data_breakpoints(seq, args),
                Command::SetInstructionBreakpoints(args) => {
                    self.handle_set_instruction_breakpoints(seq, args)
                }
                _ => {
                    self.send_error(seq, "unsupported command");
                    Ok(())
                }
            };

            if let Err(e) = result {
                let _ = self.send_output(&format!("internal error: {}", e));
            }
        }
        Ok(())
    }

    // ── Capabilities ──────────────────────────────────────────────────

    fn capabilities() -> Capabilities {
        Capabilities {
            supports_configuration_done_request: Some(true),
            supports_conditional_breakpoints: Some(true),
            supports_function_breakpoints: Some(true),
            supports_data_breakpoints: Some(true),
            supports_disassemble_request: Some(true),
            supports_read_memory_request: Some(true),
            supports_write_memory_request: Some(true),
            supports_instruction_breakpoints: Some(true),
            supports_evaluate_for_hovers: Some(true),
            exception_breakpoint_filters: Some(vec![
                ExceptionBreakpointsFilter {
                    filter: "all_signals".into(),
                    label: "All Signals".into(),
                    description: Some("Break on any signal".into()),
                    default: Some(false),
                    supports_condition: Some(false),
                    condition_description: None,
                },
                ExceptionBreakpointsFilter {
                    filter: "sigsegv".into(),
                    label: "SIGSEGV".into(),
                    description: Some("Break on segmentation fault".into()),
                    default: Some(true),
                    supports_condition: Some(false),
                    condition_description: None,
                },
                ExceptionBreakpointsFilter {
                    filter: "sigabrt".into(),
                    label: "SIGABRT".into(),
                    description: Some("Break on abort".into()),
                    default: Some(true),
                    supports_condition: Some(false),
                    condition_description: None,
                },
            ]),
            ..Default::default()
        }
    }

    // ── Request handlers ──────────────────────────────────────────────

    fn handle_initialize(
        &mut self,
        seq: i64,
        _args: &dap::requests::InitializeArguments,
    ) -> Result<()> {
        self.send_ok(seq, ResponseBody::Initialize(Self::capabilities()));
        let _ = self.server.send_event(Event::Initialized);
        Ok(())
    }

    fn handle_launch(
        &mut self,
        seq: i64,
        args: &dap::requests::LaunchRequestArguments,
    ) -> Result<()> {
        let additional = match &args.additional_data {
            Some(data) => data,
            None => {
                self.send_error(seq, "launch requires 'program' in additional data");
                return Ok(());
            }
        };

        let program = match additional.get("program").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => {
                self.send_error(seq, "missing 'program' field in launch arguments");
                return Ok(());
            }
        };

        let args_val: Vec<String> = additional
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let path = Path::new(&program);
        self.dwarf = DwarfInfo::load(path).ok();

        let args_ref: Vec<&str> = args_val.iter().map(|s| s.as_str()).collect();
        match Target::launch(path, &args_ref) {
            Ok(target) => {
                self.target = Some(target);
                self.run_security_analysis();
                self.send_ok(seq, ResponseBody::Launch);
                self.send_stopped("entry", None);
            }
            Err(e) => {
                self.send_error(seq, &format!("launch failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_attach(
        &mut self,
        seq: i64,
        args: &dap::requests::AttachRequestArguments,
    ) -> Result<()> {
        let pid = args
            .additional_data
            .as_ref()
            .and_then(|d| d.get("pid"))
            .and_then(|v| v.as_i64())
            .map(|p| p as i32);

        let pid = match pid {
            Some(p) => p,
            None => {
                self.send_error(seq, "attach requires 'pid' in additional data");
                return Ok(());
            }
        };

        match Target::attach(nix::unistd::Pid::from_raw(pid)) {
            Ok(target) => {
                let exe = target.program_path().to_string();
                self.dwarf = DwarfInfo::load(Path::new(&exe)).ok();
                self.target = Some(target);
                self.run_security_analysis();
                self.send_ok(seq, ResponseBody::Attach);
                self.send_stopped("entry", None);
            }
            Err(e) => {
                self.send_error(seq, &format!("attach failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_configuration_done(&mut self, seq: i64) -> Result<()> {
        self.send_ok(seq, ResponseBody::ConfigurationDone);
        self.apply_deferred_breakpoints();
        Ok(())
    }

    fn apply_deferred_breakpoints(&mut self) {
        if self.target.is_none() {
            return;
        }

        // Apply deferred source breakpoints.
        let deferred_src: Vec<_> = std::mem::take(&mut self.deferred_source_bps);
        let mut applied = 0usize;
        let mut failed = 0usize;
        for dbp in &deferred_src {
            let addr = self.resolve_source_line(&dbp.file, dbp.line as u32);
            if let Some(addr) = addr {
                if let Some(ref mut target) = self.target {
                    let result = if let Some(ref cond) = dbp.condition {
                        target.set_conditional_breakpoint(addr, cond.clone())
                    } else {
                        target.set_breakpoint(addr)
                    };
                    if result.is_ok() {
                        self.source_breakpoints
                            .insert((dbp.file.clone(), dbp.line), addr);
                        applied += 1;
                    } else {
                        failed += 1;
                    }
                }
            } else {
                failed += 1;
            }
        }

        // Apply deferred function breakpoints.
        let deferred_fn: Vec<_> = std::mem::take(&mut self.deferred_fn_bps);
        for dfb in &deferred_fn {
            if let Some(ref mut target) = self.target {
                if let Some(addr) = target.find_symbol(&dfb.name) {
                    let result = if let Some(ref cond) = dfb.condition {
                        target.set_conditional_breakpoint(addr, cond.clone())
                    } else {
                        target.set_breakpoint(addr)
                    };
                    if result.is_ok() {
                        applied += 1;
                    } else {
                        failed += 1;
                    }
                } else {
                    failed += 1;
                }
            }
        }

        if applied > 0 || failed > 0 {
            let _ = self.send_output(&format!(
                "deferred breakpoints: {} applied, {} failed",
                applied, failed
            ));
        }
    }

    fn handle_set_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetBreakpointsArguments,
    ) -> Result<()> {
        let source_path = args.source.path.as_deref().unwrap_or("").to_string();

        // Remove old breakpoints for this source file.
        let old_keys: Vec<(String, i64)> = self
            .source_breakpoints
            .keys()
            .filter(|(f, _)| f == &source_path)
            .cloned()
            .collect();
        for key in &old_keys {
            if let Some(addr) = self.source_breakpoints.remove(key) {
                if let Some(ref mut target) = self.target {
                    let _ = target.remove_breakpoint(addr);
                }
            }
        }

        let mut result_bps = Vec::new();

        if let Some(breakpoints) = &args.breakpoints {
            for src_bp in breakpoints {
                let line = src_bp.line;
                let addr = self.resolve_source_line(&source_path, line as u32);

                if let Some(addr) = addr {
                    let mut verified = false;
                    let bp_id = self.next_bp_id;
                    self.next_bp_id += 1;

                    if let Some(ref mut target) = self.target {
                        let set_result = if let Some(ref cond) = src_bp.condition {
                            target.set_conditional_breakpoint(addr, cond.clone())
                        } else {
                            target.set_breakpoint(addr)
                        };
                        if set_result.is_ok() {
                            verified = true;
                            self.source_breakpoints
                                .insert((source_path.clone(), line), addr);
                        }
                    } else {
                        // No target yet; defer for later application.
                        self.deferred_source_bps.push(DeferredSourceBreakpoint {
                            file: source_path.clone(),
                            line,
                            condition: src_bp.condition.clone(),
                        });
                    }

                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified,
                        source: Some(Source {
                            path: Some(source_path.clone()),
                            ..Default::default()
                        }),
                        line: Some(line),
                        ..Default::default()
                    });
                } else if self.target.is_none() {
                    // No DWARF resolution possible yet; defer entirely.
                    let bp_id = self.next_bp_id;
                    self.next_bp_id += 1;
                    self.deferred_source_bps.push(DeferredSourceBreakpoint {
                        file: source_path.clone(),
                        line,
                        condition: src_bp.condition.clone(),
                    });
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: false,
                        message: Some("deferred until target launch".into()),
                        source: Some(Source {
                            path: Some(source_path.clone()),
                            ..Default::default()
                        }),
                        line: Some(line),
                        ..Default::default()
                    });
                } else {
                    let bp_id = self.next_bp_id;
                    self.next_bp_id += 1;
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: false,
                        message: Some("could not resolve source line to address".into()),
                        ..Default::default()
                    });
                }
            }
        }

        self.send_ok(
            seq,
            ResponseBody::SetBreakpoints(dap::responses::SetBreakpointsResponse {
                breakpoints: result_bps,
            }),
        );
        Ok(())
    }

    fn handle_set_function_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetFunctionBreakpointsArguments,
    ) -> Result<()> {
        let mut result_bps = Vec::new();

        for fb in &args.breakpoints {
            let bp_id = self.next_bp_id;
            self.next_bp_id += 1;

            if let Some(ref mut target) = self.target {
                if let Some(addr) = target.find_symbol(&fb.name) {
                    let set_result = if let Some(ref cond) = fb.condition {
                        target.set_conditional_breakpoint(addr, cond.clone())
                    } else {
                        target.set_breakpoint(addr)
                    };
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: set_result.is_ok(),
                        ..Default::default()
                    });
                } else {
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: false,
                        message: Some(format!("symbol '{}' not found", fb.name)),
                        ..Default::default()
                    });
                }
            } else {
                // No target yet; defer for later application.
                self.deferred_fn_bps.push(DeferredFunctionBreakpoint {
                    name: fb.name.clone(),
                    condition: fb.condition.clone(),
                });
                result_bps.push(Breakpoint {
                    id: Some(bp_id),
                    verified: false,
                    message: Some("deferred until target launch".into()),
                    ..Default::default()
                });
            }
        }

        self.send_ok(
            seq,
            ResponseBody::SetFunctionBreakpoints(dap::responses::SetFunctionBreakpointsResponse {
                breakpoints: result_bps,
            }),
        );
        Ok(())
    }

    fn handle_set_exception_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetExceptionBreakpointsArguments,
    ) -> Result<()> {
        if let Some(ref mut target) = self.target {
            use crate::target::SignalPolicy;
            use nix::sys::signal::Signal;

            for filter in &args.filters {
                match filter.as_str() {
                    "all_signals" => {
                        // Set stop policy for common signals.
                        let signals = [
                            Signal::SIGSEGV,
                            Signal::SIGABRT,
                            Signal::SIGFPE,
                            Signal::SIGILL,
                            Signal::SIGBUS,
                            Signal::SIGTRAP,
                        ];
                        for sig in &signals {
                            target.set_signal_policy(
                                *sig,
                                SignalPolicy {
                                    stop: true,
                                    pass: false,
                                },
                            );
                        }
                    }
                    "sigsegv" => {
                        target.set_signal_policy(
                            Signal::SIGSEGV,
                            SignalPolicy {
                                stop: true,
                                pass: false,
                            },
                        );
                    }
                    "sigabrt" => {
                        target.set_signal_policy(
                            Signal::SIGABRT,
                            SignalPolicy {
                                stop: true,
                                pass: false,
                            },
                        );
                    }
                    _ => {}
                }
            }
        }

        self.send_ok(
            seq,
            ResponseBody::SetExceptionBreakpoints(
                dap::responses::SetExceptionBreakpointsResponse { breakpoints: None },
            ),
        );
        Ok(())
    }

    fn handle_continue(&mut self, seq: i64, args: &dap::requests::ContinueArguments) -> Result<()> {
        if self.target.is_none() {
            self.send_error(seq, "no active debug target");
            return Ok(());
        }

        if let Err(e) = self.switch_to_thread(args.thread_id) {
            self.send_error(seq, &e);
            return Ok(());
        }

        self.variable_refs.clear();
        self.next_var_ref = 1;

        match self.target.as_mut().unwrap().resume() {
            Ok(reason) => {
                self.send_ok(
                    seq,
                    ResponseBody::Continue(dap::responses::ContinueResponse {
                        all_threads_continued: Some(true),
                    }),
                );
                self.handle_stop_reason(&reason);
                self.emit_automation_events();
            }
            Err(e) => {
                self.send_error(seq, &format!("continue failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_next(&mut self, seq: i64, args: &dap::requests::NextArguments) -> Result<()> {
        self.do_step(seq, "next", args.thread_id)
    }

    fn handle_step_in(&mut self, seq: i64, args: &dap::requests::StepInArguments) -> Result<()> {
        self.do_step(seq, "stepIn", args.thread_id)
    }

    fn handle_step_out(&mut self, seq: i64, args: &dap::requests::StepOutArguments) -> Result<()> {
        self.do_step(seq, "stepOut", args.thread_id)
    }

    fn do_step(&mut self, seq: i64, kind: &str, thread_id: i64) -> Result<()> {
        if self.target.is_none() {
            self.send_error(seq, "no active debug target");
            return Ok(());
        }

        if let Err(e) = self.switch_to_thread(thread_id) {
            self.send_error(seq, &e);
            return Ok(());
        }

        self.variable_refs.clear();
        self.next_var_ref = 1;

        let target = self.target.as_mut().unwrap();
        let result = match kind {
            "next" => target.step_over(),
            "stepIn" => target.step_in(),
            "stepOut" => target.step_out(),
            _ => unreachable!(),
        };

        match result {
            Ok(reason) => {
                let body = match kind {
                    "next" => ResponseBody::Next,
                    "stepIn" => ResponseBody::StepIn,
                    "stepOut" => ResponseBody::StepOut,
                    _ => unreachable!(),
                };
                self.send_ok(seq, body);
                self.handle_stop_reason(&reason);
                self.emit_automation_events();
            }
            Err(e) => {
                self.send_error(seq, &format!("{} failed: {}", kind, e));
            }
        }
        Ok(())
    }

    fn handle_pause(&mut self, seq: i64, args: &dap::requests::PauseArguments) -> Result<()> {
        if self.target.is_some() {
            use nix::sys::signal;
            let tid = Pid::from_raw(args.thread_id as i32);
            let _ = signal::kill(tid, signal::Signal::SIGSTOP);
            self.send_ok(seq, ResponseBody::Pause);
        } else {
            self.send_error(seq, "no active debug target");
        }
        Ok(())
    }

    fn handle_threads(&mut self, seq: i64) -> Result<()> {
        let threads = if let Some(ref target) = self.target {
            target
                .thread_list()
                .iter()
                .map(|tid| Thread {
                    id: tid.as_raw() as i64,
                    name: format!("Thread {}", tid),
                })
                .collect()
        } else {
            vec![]
        };

        self.send_ok(
            seq,
            ResponseBody::Threads(dap::responses::ThreadsResponse { threads }),
        );
        Ok(())
    }

    fn handle_stack_trace(
        &mut self,
        seq: i64,
        args: &dap::requests::StackTraceArguments,
    ) -> Result<()> {
        if self.target.is_none() {
            self.send_error(seq, "no active debug target");
            return Ok(());
        }

        if let Err(e) = self.switch_to_thread(args.thread_id) {
            self.send_error(seq, &e);
            return Ok(());
        }

        match self.target.as_ref().unwrap().backtrace() {
            Ok(frames) => {
                let stack_frames: Vec<StackFrame> = frames.iter().map(format_stack_frame).collect();
                let total = stack_frames.len() as i64;
                self.send_ok(
                    seq,
                    ResponseBody::StackTrace(dap::responses::StackTraceResponse {
                        stack_frames,
                        total_frames: Some(total),
                    }),
                );
            }
            Err(e) => {
                self.send_error(seq, &format!("backtrace failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_scopes(&mut self, seq: i64, args: &dap::requests::ScopesArguments) -> Result<()> {
        let locals_ref = self.alloc_var_ref();
        self.variable_refs
            .insert(locals_ref, VariableScope::Locals(args.frame_id));

        let regs_ref = self.alloc_var_ref();
        self.variable_refs
            .insert(regs_ref, VariableScope::Registers);

        let scopes = vec![
            Scope {
                name: "Locals".into(),
                presentation_hint: Some(dap::types::ScopePresentationhint::Locals),
                variables_reference: locals_ref,
                expensive: false,
                ..Default::default()
            },
            Scope {
                name: "Registers".into(),
                presentation_hint: Some(dap::types::ScopePresentationhint::Registers),
                variables_reference: regs_ref,
                expensive: false,
                ..Default::default()
            },
        ];

        self.send_ok(
            seq,
            ResponseBody::Scopes(dap::responses::ScopesResponse { scopes }),
        );
        Ok(())
    }

    fn handle_variables(
        &mut self,
        seq: i64,
        args: &dap::requests::VariablesArguments,
    ) -> Result<()> {
        let var_ref = args.variables_reference;

        let scope = match self.variable_refs.get(&var_ref) {
            Some(s) => s,
            None => {
                self.send_ok(
                    seq,
                    ResponseBody::Variables(dap::responses::VariablesResponse {
                        variables: vec![],
                    }),
                );
                return Ok(());
            }
        };

        let variables = match scope {
            VariableScope::Locals(_frame_id) => self.get_local_variables(),
            VariableScope::Registers => self.get_register_variables(),
            VariableScope::Children(children) => {
                let children = children.clone();
                children
                    .iter()
                    .map(|(name, value, ty)| dap::types::Variable {
                        name: name.clone(),
                        value: value.clone(),
                        type_field: Some(ty.clone()),
                        variables_reference: 0,
                        ..Default::default()
                    })
                    .collect()
            }
        };

        self.send_ok(
            seq,
            ResponseBody::Variables(dap::responses::VariablesResponse { variables }),
        );
        Ok(())
    }

    fn handle_evaluate(&mut self, seq: i64, args: &dap::requests::EvaluateArguments) -> Result<()> {
        let expr = args.expression.trim();

        // Handle automation queries ($events, $bypass, $secrets)
        if let Some(result) = self.evaluate_automation_query(expr) {
            self.send_ok(
                seq,
                ResponseBody::Evaluate(dap::responses::EvaluateResponse {
                    result,
                    type_field: None,
                    presentation_hint: None,
                    variables_reference: 0,
                    named_variables: None,
                    indexed_variables: None,
                    memory_reference: None,
                }),
            );
            return Ok(());
        }

        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        match target.read_variable(expr) {
            Ok(Some((_var, formatted))) => {
                self.send_ok(
                    seq,
                    ResponseBody::Evaluate(dap::responses::EvaluateResponse {
                        result: formatted,
                        type_field: None,
                        presentation_hint: None,
                        variables_reference: 0,
                        named_variables: None,
                        indexed_variables: None,
                        memory_reference: None,
                    }),
                );
            }
            Ok(None) => {
                self.send_error(seq, &format!("variable '{}' not found", expr));
            }
            Err(e) => {
                self.send_error(seq, &format!("evaluate failed: {}", e));
            }
        }
        Ok(())
    }

    /// Handle automation queries typed in the debug console.
    fn evaluate_automation_query(&self, expr: &str) -> Option<String> {
        let target = self.target.as_ref()?;
        match expr {
            "$events" => {
                let log = target.event_log();
                let n = log.len();
                if n == 0 {
                    return Some("no events recorded".into());
                }
                let last = log.last_n(20);
                let mut lines = vec![format!("{} events total (last 20):", n)];
                for e in last {
                    lines.push(format!(
                        "[{:>6}] {:>10.3}s  {}",
                        e.seq,
                        e.elapsed.as_secs_f64(),
                        e.kind.format_oneline()
                    ));
                }
                Some(lines.join("\n"))
            }
            "$bypass" => {
                let engine = target.bypass_engine();
                let stats = engine.stats();
                let config = engine.config();
                let lines = vec![
                    "Anti-analysis bypass status:".into(),
                    format!(
                        "  ptrace: {} ({})",
                        if config.bypass_ptrace { "ON" } else { "OFF" },
                        stats.ptrace_bypassed
                    ),
                    format!(
                        "  proc/status: {} ({})",
                        if config.bypass_proc_status {
                            "ON"
                        } else {
                            "OFF"
                        },
                        stats.proc_status_spoofed
                    ),
                    format!(
                        "  timers: {} ({})",
                        if config.neutralize_watchdog_timers {
                            "ON"
                        } else {
                            "OFF"
                        },
                        stats.timers_neutralized
                    ),
                    format!(
                        "  self-signals: {} ({})",
                        if config.suppress_self_signals {
                            "ON"
                        } else {
                            "OFF"
                        },
                        stats.self_signals_suppressed
                    ),
                ];
                Some(lines.join("\n"))
            }
            "$secrets" => {
                let findings = target.secret_scanner().findings();
                if findings.is_empty() {
                    return Some("no secrets found".into());
                }
                let mut lines = vec![format!("{} secrets found:", findings.len())];
                for f in &findings {
                    lines.push(format!(
                        "  [{}] {} bytes at {}{}",
                        f.category,
                        f.size,
                        f.addr,
                        f.pattern_name
                            .as_ref()
                            .map(|p| format!(" ({})", p))
                            .unwrap_or_default()
                    ));
                }
                Some(lines.join("\n"))
            }
            _ => None,
        }
    }

    fn handle_disassemble(
        &mut self,
        seq: i64,
        args: &dap::requests::DisassembleArguments,
    ) -> Result<()> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        let addr = match parse_address(&args.memory_reference) {
            Ok(a) => a,
            Err(e) => {
                self.send_error(seq, &e);
                return Ok(());
            }
        };
        let offset = args.instruction_offset.unwrap_or(0);
        if args.instruction_count < 0 {
            self.send_error(seq, "instruction_count must be non-negative");
            return Ok(());
        }
        let count = (args.instruction_count as usize).min(MAX_INSTRUCTION_COUNT);
        let start = if offset >= 0 {
            addr + offset as u64
        } else {
            addr.saturating_sub((-offset) as u64)
        };

        match target.disassemble(VirtAddr(start), count, DisasmStyle::Intel) {
            Ok(instrs) => {
                let instructions: Vec<DisassembledInstruction> = instrs
                    .iter()
                    .map(|i| DisassembledInstruction {
                        address: format!("0x{:x}", i.addr.addr()),
                        instruction: i.text.clone(),
                        instruction_bytes: Some(
                            i.bytes
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" "),
                        ),
                        ..Default::default()
                    })
                    .collect();

                self.send_ok(
                    seq,
                    ResponseBody::Disassemble(dap::responses::DisassembleResponse { instructions }),
                );
            }
            Err(e) => {
                self.send_error(seq, &format!("disassemble failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_read_memory(
        &mut self,
        seq: i64,
        args: &dap::requests::ReadMemoryArguments,
    ) -> Result<()> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        let addr = match parse_address(&args.memory_reference) {
            Ok(a) => a,
            Err(e) => {
                self.send_error(seq, &e);
                return Ok(());
            }
        };
        let offset = args.offset.unwrap_or(0);
        let start = if offset >= 0 {
            addr + offset as u64
        } else {
            addr.saturating_sub((-offset) as u64)
        };
        if args.count < 0 {
            self.send_error(seq, "count must be non-negative");
            return Ok(());
        }
        let count = (args.count as usize).min(MAX_MEMORY_REQUEST);

        match target.read_memory(VirtAddr(start), count) {
            Ok(data) => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
                self.send_ok(
                    seq,
                    ResponseBody::ReadMemory(dap::responses::ReadMemoryResponse {
                        address: format!("0x{:x}", start),
                        unreadable_bytes: None,
                        data: Some(encoded),
                    }),
                );
            }
            Err(e) => {
                self.send_error(seq, &format!("read memory failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_write_memory(
        &mut self,
        seq: i64,
        args: &dap::requests::WriteMemoryArguments,
    ) -> Result<()> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        let addr = match parse_address(&args.memory_reference) {
            Ok(a) => a,
            Err(e) => {
                self.send_error(seq, &e);
                return Ok(());
            }
        };
        let offset = args.offset.unwrap_or(0);
        let start = if offset >= 0 {
            addr + offset as u64
        } else {
            addr.saturating_sub((-offset) as u64)
        };

        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(&args.data) {
            Ok(d) => d,
            Err(e) => {
                self.send_error(seq, &format!("base64 decode failed: {}", e));
                return Ok(());
            }
        };

        match target.write_memory(VirtAddr(start), &decoded) {
            Ok(()) => {
                self.send_ok(
                    seq,
                    ResponseBody::WriteMemory(dap::responses::WriteMemoryResponse {
                        offset: None,
                        bytes_written: Some(decoded.len() as i64),
                    }),
                );
            }
            Err(e) => {
                self.send_error(seq, &format!("write memory failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_set_data_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetDataBreakpointsArguments,
    ) -> Result<()> {
        // Remove all existing data breakpoints.
        if let Some(ref mut target) = self.target {
            for (_data_id, wp_id) in self.data_breakpoints.drain() {
                let _ = target.remove_watchpoint(wp_id);
            }
        } else {
            self.data_breakpoints.clear();
        }

        let mut result_bps = Vec::new();

        for dbp in &args.breakpoints {
            let bp_id = self.next_bp_id;
            self.next_bp_id += 1;

            if let Some(ref mut target) = self.target {
                let addr = match parse_address(&dbp.data_id) {
                    Ok(a) => a,
                    Err(_) => {
                        result_bps.push(Breakpoint {
                            id: Some(bp_id),
                            verified: false,
                            message: Some(format!("invalid address: {}", dbp.data_id)),
                            ..Default::default()
                        });
                        continue;
                    }
                };
                let wp_type = match dbp.access_type {
                    Some(dap::types::DataBreakpointAccessType::Write) => WatchpointType::Write,
                    Some(dap::types::DataBreakpointAccessType::Read) => WatchpointType::ReadWrite,
                    Some(dap::types::DataBreakpointAccessType::ReadWrite) => {
                        WatchpointType::ReadWrite
                    }
                    None => WatchpointType::Write,
                };

                match target.set_watchpoint(VirtAddr(addr), wp_type, WatchpointSize::Byte8) {
                    Ok(wp_id) => {
                        self.data_breakpoints.insert(dbp.data_id.clone(), wp_id);
                        result_bps.push(Breakpoint {
                            id: Some(bp_id),
                            verified: true,
                            ..Default::default()
                        });
                    }
                    Err(_) => {
                        result_bps.push(Breakpoint {
                            id: Some(bp_id),
                            verified: false,
                            message: Some("failed to set data breakpoint".into()),
                            ..Default::default()
                        });
                    }
                }
            } else {
                result_bps.push(Breakpoint {
                    id: Some(bp_id),
                    verified: false,
                    message: Some("no active debug target".into()),
                    ..Default::default()
                });
            }
        }

        self.send_ok(
            seq,
            ResponseBody::SetDataBreakpoints(dap::responses::SetDataBreakpointsResponse {
                breakpoints: result_bps,
            }),
        );
        Ok(())
    }

    fn handle_set_instruction_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetInstructionBreakpointsArguments,
    ) -> Result<()> {
        // Remove all existing instruction breakpoints.
        if let Some(ref mut target) = self.target {
            for addr in self.instruction_breakpoints.drain(..) {
                let _ = target.remove_breakpoint(addr);
            }
        } else {
            self.instruction_breakpoints.clear();
        }

        let mut result_bps = Vec::new();

        for ib in &args.breakpoints {
            let bp_id = self.next_bp_id;
            self.next_bp_id += 1;

            if let Some(ref mut target) = self.target {
                let addr = match parse_address(&ib.instruction_reference) {
                    Ok(a) => a,
                    Err(_) => {
                        result_bps.push(Breakpoint {
                            id: Some(bp_id),
                            verified: false,
                            message: Some(format!("invalid address: {}", ib.instruction_reference)),
                            ..Default::default()
                        });
                        continue;
                    }
                };
                let offset = ib.offset.unwrap_or(0);
                let start = if offset >= 0 {
                    addr + offset as u64
                } else {
                    addr.saturating_sub((-offset) as u64)
                };
                let target_addr = VirtAddr(start);

                let set_result = if let Some(ref cond) = ib.condition {
                    target.set_conditional_breakpoint(target_addr, cond.clone())
                } else {
                    target.set_breakpoint(target_addr)
                };

                if set_result.is_ok() {
                    self.instruction_breakpoints.push(target_addr);
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: true,
                        instruction_reference: Some(format!("0x{:x}", start)),
                        ..Default::default()
                    });
                } else {
                    result_bps.push(Breakpoint {
                        id: Some(bp_id),
                        verified: false,
                        message: Some("failed to set instruction breakpoint".into()),
                        ..Default::default()
                    });
                }
            } else {
                result_bps.push(Breakpoint {
                    id: Some(bp_id),
                    verified: false,
                    message: Some("no active debug target".into()),
                    ..Default::default()
                });
            }
        }

        self.send_ok(
            seq,
            ResponseBody::SetInstructionBreakpoints(
                dap::responses::SetInstructionBreakpointsResponse {
                    breakpoints: result_bps,
                },
            ),
        );
        Ok(())
    }

    // ── Stop reason mapping ───────────────────────────────────────────

    fn handle_stop_reason(&mut self, reason: &StopReason) {
        match reason {
            StopReason::BreakpointHit { .. } => {
                self.send_stopped("breakpoint", None);
            }
            StopReason::SingleStep => {
                self.send_stopped("step", None);
            }
            StopReason::Signal(sig) => {
                self.send_stopped_with_text("exception", &format!("{}", sig));
            }
            StopReason::WatchpointHit { .. } => {
                self.send_stopped("data breakpoint", None);
            }
            StopReason::SyscallEntry { number, .. } => {
                let name = crate::syscall::name(*number)
                    .unwrap_or("unknown")
                    .to_string();
                self.send_stopped_with_text("exception", &format!("syscall entry: {}", name));
            }
            StopReason::SyscallExit { number, .. } => {
                let name = crate::syscall::name(*number)
                    .unwrap_or("unknown")
                    .to_string();
                self.send_stopped_with_text("exception", &format!("syscall exit: {}", name));
            }
            StopReason::Exited(code) => {
                let _ = self.server.send_event(Event::Exited(ExitedEventBody {
                    exit_code: *code as i64,
                }));
                let _ = self.server.send_event(Event::Terminated(None));
                self.target = None;
            }
            StopReason::Terminated(sig) => {
                let _ = self
                    .server
                    .send_event(Event::Exited(ExitedEventBody { exit_code: -1 }));
                let _ = self.send_output(&format!("terminated by signal: {}", sig));
                let _ = self.server.send_event(Event::Terminated(None));
                self.target = None;
            }
            StopReason::ThreadCreated(tid) => {
                let _ = self.server.send_event(Event::Thread(ThreadEventBody {
                    reason: dap::types::ThreadEventReason::Started,
                    thread_id: tid.as_raw() as i64,
                }));
            }
            StopReason::ThreadExited(tid) => {
                let _ = self.server.send_event(Event::Thread(ThreadEventBody {
                    reason: dap::types::ThreadEventReason::Exited,
                    thread_id: tid.as_raw() as i64,
                }));
            }
        }
    }

    // ── Variable helpers ──────────────────────────────────────────────

    fn alloc_var_ref(&mut self) -> i64 {
        let r = self.next_var_ref;
        self.next_var_ref += 1;
        r
    }

    fn get_local_variables(&mut self) -> Vec<dap::types::Variable> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => return vec![],
        };

        let vars = match target.list_variables() {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        // Collect variable data first (borrows target immutably),
        // then create child refs (borrows self mutably).
        let var_data: Vec<_> = vars
            .into_iter()
            .map(|var| {
                let data_result = target.read_variable_data(&var.name);
                match data_result {
                    Ok(Some((_, data))) => {
                        let read_mem =
                            |addr: u64, len: usize| target.read_memory(VirtAddr(addr), len);
                        let formatted =
                            rust_type::format_rust_value(&data, &var.type_info, &read_mem)
                                .unwrap_or_else(|| variables::format_value(&data, &var.type_info));
                        (var, formatted, Some(data))
                    }
                    _ => {
                        // Fall back to read_variable for formatted string
                        let formatted = target
                            .read_variable(&var.name)
                            .ok()
                            .flatten()
                            .map(|(_, f)| f)
                            .unwrap_or_else(|| "<unavailable>".into());
                        (var, formatted, None)
                    }
                }
            })
            .collect();

        let mut result = Vec::new();
        for (var, formatted, data) in var_data {
            let child_ref = match data {
                Some(ref d) => self.maybe_create_child_ref(&var, d),
                None => self.maybe_create_child_ref(&var, &[]),
            };

            result.push(dap::types::Variable {
                name: var.name.clone(),
                value: formatted,
                type_field: Some(var.type_info.name.clone()),
                variables_reference: child_ref,
                ..Default::default()
            });
        }
        result
    }

    fn get_register_variables(&self) -> Vec<dap::types::Variable> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => return vec![],
        };

        match target.read_registers() {
            Ok(regs) => regs
                .iter()
                .map(|(name, val)| dap::types::Variable {
                    name: name.to_string(),
                    value: format!("0x{:x}", val),
                    type_field: Some("u64".into()),
                    variables_reference: 0,
                    ..Default::default()
                })
                .collect(),
            Err(_) => vec![],
        }
    }

    fn maybe_create_child_ref(&mut self, var: &Variable, data: &[u8]) -> i64 {
        match &var.type_info.kind {
            TypeKind::Struct(members) if !members.is_empty() => {
                let children: Vec<(String, String, String)> = members
                    .iter()
                    .map(|m| {
                        let value = Self::format_member_value(m, data);
                        (m.name.clone(), value, m.type_info.name.clone())
                    })
                    .collect();
                let r = self.alloc_var_ref();
                self.variable_refs
                    .insert(r, VariableScope::Children(children));
                r
            }
            TypeKind::Union(members) if !members.is_empty() => {
                let children: Vec<(String, String, String)> = members
                    .iter()
                    .map(|m| {
                        let value = Self::format_member_value(m, data);
                        (m.name.clone(), value, m.type_info.name.clone())
                    })
                    .collect();
                let r = self.alloc_var_ref();
                self.variable_refs
                    .insert(r, VariableScope::Children(children));
                r
            }
            TypeKind::Enum {
                discriminant,
                variants,
            } if !variants.is_empty() => {
                // Read discriminant to find the active variant
                let discr_val = discriminant.as_ref().and_then(|d| {
                    let start = d.offset as usize;
                    let dsize = d.type_info.byte_size as usize;
                    let end = start + dsize;
                    if end <= data.len() {
                        match dsize {
                            1 => Some(data[start] as u64),
                            2 => Some(u16::from_le_bytes(data[start..end].try_into().ok()?) as u64),
                            4 => Some(u32::from_le_bytes(data[start..end].try_into().ok()?) as u64),
                            8 => Some(u64::from_le_bytes(data[start..end].try_into().ok()?)),
                            _ => None,
                        }
                    } else {
                        None
                    }
                });

                // Find matching variant (or default with discr_value == None)
                let active = discr_val
                    .and_then(|dv| variants.iter().find(|v| v.discr_value == Some(dv)))
                    .or_else(|| variants.iter().find(|v| v.discr_value.is_none()));

                if let Some(v) = active {
                    if v.members.is_empty() {
                        // Unit variant — no children to expand
                        return 0;
                    }
                    // Show the active variant's fields as children
                    let children: Vec<(String, String, String)> = v
                        .members
                        .iter()
                        .flat_map(|m| {
                            // Each variant member is typically a struct wrapping the fields
                            if let TypeKind::Struct(fields) = &m.type_info.kind {
                                fields
                                    .iter()
                                    .map(|f| {
                                        let start = m.offset as usize + f.offset as usize;
                                        let end = start + f.type_info.byte_size as usize;
                                        let value = if end <= data.len() {
                                            variables::format_value(&data[start..end], &f.type_info)
                                        } else {
                                            "<?>".into()
                                        };
                                        (f.name.clone(), value, f.type_info.name.clone())
                                    })
                                    .collect::<Vec<_>>()
                            } else {
                                let value = Self::format_member_value(m, data);
                                vec![(m.name.clone(), value, m.type_info.name.clone())]
                            }
                        })
                        .collect();
                    if children.is_empty() {
                        return 0;
                    }
                    let r = self.alloc_var_ref();
                    self.variable_refs
                        .insert(r, VariableScope::Children(children));
                    r
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Format a struct/union member's value from raw parent data.
    fn format_member_value(m: &variables::MemberInfo, data: &[u8]) -> String {
        let start = m.offset as usize;
        let end = start + m.type_info.byte_size as usize;
        if data.is_empty() || end > data.len() {
            return format!("<{}>", m.type_info.name);
        }
        let member_data = &data[start..end];
        variables::format_value(member_data, &m.type_info)
    }

    // ── Thread switching ───────────────────────────────────────────────

    fn switch_to_thread(&mut self, thread_id: i64) -> std::result::Result<(), String> {
        let target = self
            .target
            .as_mut()
            .ok_or_else(|| "no active debug target".to_string())?;
        let tid = Pid::from_raw(thread_id as i32);
        target
            .switch_thread(tid)
            .map_err(|e| format!("switch_thread: {}", e))
    }

    // ── Security analysis ──────────────────────────────────────────────

    fn run_security_analysis(&mut self) {
        let path = match self.target.as_ref() {
            Some(t) => t.program_path().to_string(),
            None => return,
        };

        if let Ok(result) = checksec::checksec(Path::new(&path)) {
            let _ = self.send_output(&format_checksec(&result, &path));
        }

        if let Ok(findings) = antidebug::scan(Path::new(&path)) {
            if !findings.is_empty() {
                let _ = self.send_output(&format_antidebug(&findings));
            }
        }
    }

    // ── Source line resolution ─────────────────────────────────────────

    fn resolve_source_line(&self, file: &str, line: u32) -> Option<VirtAddr> {
        self.dwarf.as_ref()?.find_address(file, line).ok()?
    }

    // ── Automation event emission ─────────────────────────────────────

    /// Send new automation events (bypasses, secrets) to the editor's debug console.
    /// Called after each stop event so the editor shows real-time updates.
    fn emit_automation_events(&mut self) {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => return,
        };

        let log = target.event_log();
        let events = log.events();
        let new_start = self.last_emitted_event;
        if new_start >= events.len() {
            return;
        }

        for event in &events[new_start..] {
            let category = event.kind.category();
            match category {
                crate::event_log::EventCategory::AntiDebug => {
                    let _ = self.send_output(&format!("[bypass] {}", event.kind.format_oneline()));
                }
                crate::event_log::EventCategory::Secret => {
                    let _ = self.send_output(&format!("[secret] {}", event.kind.format_oneline()));
                }
                _ => {} // Syscalls/signals are already shown via stopped events
            }
        }
        self.last_emitted_event = events.len();
    }

    // ── Response helpers ──────────────────────────────────────────────

    fn send_ok(&mut self, request_seq: i64, body: ResponseBody) {
        let _ = self.server.respond(Response {
            request_seq,
            success: true,
            message: None,
            body: Some(body),
            error: None,
        });
    }

    fn send_error(&mut self, request_seq: i64, msg: &str) {
        let _ = self.server.respond(Response {
            request_seq,
            success: false,
            message: Some(dap::responses::ResponseMessage::Error(msg.to_string())),
            body: None,
            error: None,
        });
    }

    fn send_stopped(&mut self, reason: &str, bp_ids: Option<Vec<i64>>) {
        let thread_id = self
            .target
            .as_ref()
            .map(|t| t.current_tid().as_raw() as i64);

        let _ = self.server.send_event(Event::Stopped(StoppedEventBody {
            reason: stopped_reason_from_str(reason),
            description: None,
            thread_id,
            preserve_focus_hint: None,
            text: None,
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: bp_ids,
        }));
    }

    fn send_stopped_with_text(&mut self, reason: &str, text: &str) {
        let thread_id = self
            .target
            .as_ref()
            .map(|t| t.current_tid().as_raw() as i64);

        let _ = self.server.send_event(Event::Stopped(StoppedEventBody {
            reason: stopped_reason_from_str(reason),
            description: Some(text.to_string()),
            thread_id,
            preserve_focus_hint: None,
            text: Some(text.to_string()),
            all_threads_stopped: Some(true),
            hit_breakpoint_ids: None,
        }));
    }

    fn send_output(&mut self, msg: &str) -> Result<()> {
        let _ = self.server.send_event(Event::Output(OutputEventBody {
            category: Some(dap::types::OutputEventCategory::Console),
            output: format!("{}\n", msg),
            ..Default::default()
        }));
        Ok(())
    }
}

// ── Free functions ────────────────────────────────────────────────────

/// Convert a BacktraceFrame to a DAP StackFrame.
fn format_stack_frame(frame: &crate::target::BacktraceFrame) -> StackFrame {
    let source = frame.location.as_ref().map(|loc| Source {
        name: Some(loc.file.rsplit('/').next().unwrap_or(&loc.file).to_string()),
        path: Some(loc.file.clone()),
        ..Default::default()
    });

    let (line, column) = frame
        .location
        .as_ref()
        .map(|loc| (loc.line as i64, loc.column.unwrap_or(0) as i64))
        .unwrap_or((0, 0));

    StackFrame {
        id: frame.index as i64,
        name: frame
            .function
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", frame.pc.addr())),
        source,
        line,
        column,
        instruction_pointer_reference: Some(format!("0x{:x}", frame.pc.addr())),
        ..Default::default()
    }
}

/// Map a stop reason string to a DAP StoppedEventReason.
fn stopped_reason_from_str(s: &str) -> dap::types::StoppedEventReason {
    match s {
        "step" => dap::types::StoppedEventReason::Step,
        "breakpoint" => dap::types::StoppedEventReason::Breakpoint,
        "exception" => dap::types::StoppedEventReason::Exception,
        "pause" => dap::types::StoppedEventReason::Pause,
        "entry" => dap::types::StoppedEventReason::Entry,
        "data breakpoint" => dap::types::StoppedEventReason::Data,
        other => dap::types::StoppedEventReason::String(other.to_string()),
    }
}

/// Maximum bytes allowed for a single memory read/write or disassembly request.
/// Prevents DoS via oversized allocations from untrusted DAP input.
const MAX_MEMORY_REQUEST: usize = 16 * 1024 * 1024; // 16 MB

/// Maximum instruction count for disassembly requests.
const MAX_INSTRUCTION_COUNT: usize = 10_000;

/// Parse a hex address string (with optional "0x" prefix) to u64.
/// Returns an error for malformed input instead of silently falling back to 0.
fn parse_address(s: &str) -> std::result::Result<u64, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|_| format!("invalid address: {:?}", s))
}

/// Map a StopReason to a DAP stopped reason string.
pub fn stop_reason_to_stopped_reason(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::BreakpointHit { .. } => "breakpoint",
        StopReason::SingleStep => "step",
        StopReason::Signal(_) => "exception",
        StopReason::WatchpointHit { .. } => "data breakpoint",
        StopReason::SyscallEntry { .. } => "exception",
        StopReason::SyscallExit { .. } => "exception",
        StopReason::Exited(_) => "exited",
        StopReason::Terminated(_) => "terminated",
        StopReason::ThreadCreated(_) => "thread",
        StopReason::ThreadExited(_) => "thread",
    }
}

/// Format checksec results for DAP output.
fn format_checksec(result: &ChecksecResult, path: &str) -> String {
    let yn = |b: bool| if b { "Yes" } else { "No" };
    format!(
        "[Security] checksec: {}\n\
         \x20 RELRO:    {}\n\
         \x20 Canary:   {}\n\
         \x20 NX:       {}\n\
         \x20 PIE:      {}\n\
         \x20 Fortify:  {}\n\
         \x20 RPATH:    {}\n\
         \x20 RUNPATH:  {}",
        path,
        result.relro,
        yn(result.canary),
        yn(result.nx),
        yn(result.pie),
        yn(result.fortify),
        yn(result.rpath),
        yn(result.runpath),
    )
}

/// Format anti-debug findings for DAP output.
fn format_antidebug(findings: &[antidebug::AntiDebugFinding]) -> String {
    let mut out = format!(
        "[Security] anti-debug techniques detected ({}):",
        findings.len()
    );
    for f in findings {
        if f.addr != 0 {
            out.push_str(&format!(
                "\n  {} at 0x{:x}: {}",
                f.technique, f.addr, f.description
            ));
        } else {
            out.push_str(&format!("\n  {}: {}", f.technique, f.description));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VirtAddr;

    #[test]
    fn stop_reason_to_stopped_reason_all_variants() {
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::BreakpointHit {
                addr: VirtAddr(0x401000)
            }),
            "breakpoint"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::SingleStep),
            "step"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::Signal(nix::sys::signal::Signal::SIGSEGV)),
            "exception"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::WatchpointHit {
                slot: 0,
                addr: VirtAddr(0x600000)
            }),
            "data breakpoint"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::SyscallEntry {
                number: 1,
                args: [0; 6]
            }),
            "exception"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::SyscallExit {
                number: 1,
                retval: 0
            }),
            "exception"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::Exited(0)),
            "exited"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::Terminated(
                nix::sys::signal::Signal::SIGKILL
            )),
            "terminated"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::ThreadCreated(nix::unistd::Pid::from_raw(
                1234
            ))),
            "thread"
        );
        assert_eq!(
            stop_reason_to_stopped_reason(&StopReason::ThreadExited(nix::unistd::Pid::from_raw(
                1234
            ))),
            "thread"
        );
    }

    #[test]
    fn switch_to_thread_no_target() {
        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        assert!(server.target.is_none());
        let result = server.switch_to_thread(1234);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no active debug target"));
    }

    #[test]
    fn capabilities_are_set() {
        let caps = DapServer::<std::io::Stdin, std::io::Stdout>::capabilities();
        assert_eq!(caps.supports_configuration_done_request, Some(true));
        assert_eq!(caps.supports_conditional_breakpoints, Some(true));
        assert_eq!(caps.supports_function_breakpoints, Some(true));
        assert_eq!(caps.supports_data_breakpoints, Some(true));
        assert_eq!(caps.supports_disassemble_request, Some(true));
        assert_eq!(caps.supports_read_memory_request, Some(true));
        assert_eq!(caps.supports_write_memory_request, Some(true));
        assert_eq!(caps.supports_instruction_breakpoints, Some(true));
        assert_eq!(caps.supports_evaluate_for_hovers, Some(true));

        let filters = caps.exception_breakpoint_filters.unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(filters[0].filter, "all_signals");
        assert_eq!(filters[1].filter, "sigsegv");
        assert_eq!(filters[2].filter, "sigabrt");
    }

    #[test]
    fn format_stack_frame_with_location() {
        use crate::dwarf::SourceLocation;

        let frame = crate::target::BacktraceFrame {
            index: 0,
            pc: VirtAddr(0x401234),
            function: Some("main".into()),
            location: Some(SourceLocation {
                file: "/home/user/project/src/main.rs".into(),
                line: 42,
                column: Some(5),
            }),
        };

        let sf = format_stack_frame(&frame);
        assert_eq!(sf.id, 0);
        assert_eq!(sf.name, "main");
        assert_eq!(sf.line, 42);
        assert_eq!(sf.column, 5);
        assert_eq!(sf.instruction_pointer_reference, Some("0x401234".into()));

        let source = sf.source.unwrap();
        assert_eq!(source.name, Some("main.rs".into()));
        assert_eq!(source.path, Some("/home/user/project/src/main.rs".into()));
    }

    #[test]
    fn format_stack_frame_without_location() {
        let frame = crate::target::BacktraceFrame {
            index: 3,
            pc: VirtAddr(0xdeadbeef),
            function: None,
            location: None,
        };

        let sf = format_stack_frame(&frame);
        assert_eq!(sf.id, 3);
        assert_eq!(sf.name, "0xdeadbeef");
        assert_eq!(sf.line, 0);
        assert_eq!(sf.column, 0);
        assert!(sf.source.is_none());
    }

    #[test]
    fn stopped_reason_mapping() {
        assert!(matches!(
            stopped_reason_from_str("step"),
            dap::types::StoppedEventReason::Step
        ));
        assert!(matches!(
            stopped_reason_from_str("breakpoint"),
            dap::types::StoppedEventReason::Breakpoint
        ));
        assert!(matches!(
            stopped_reason_from_str("exception"),
            dap::types::StoppedEventReason::Exception
        ));
        assert!(matches!(
            stopped_reason_from_str("pause"),
            dap::types::StoppedEventReason::Pause
        ));
        assert!(matches!(
            stopped_reason_from_str("entry"),
            dap::types::StoppedEventReason::Entry
        ));
        assert!(matches!(
            stopped_reason_from_str("data breakpoint"),
            dap::types::StoppedEventReason::Data
        ));
        assert!(matches!(
            stopped_reason_from_str("custom_reason"),
            dap::types::StoppedEventReason::String(_)
        ));
    }

    #[test]
    fn parse_address_hex() {
        assert_eq!(parse_address("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_address("0X401000").unwrap(), 0x401000);
        assert_eq!(parse_address("401000").unwrap(), 0x401000);
        assert_eq!(parse_address("0").unwrap(), 0);
        assert!(parse_address("not_hex").is_err());
        assert!(parse_address("").is_err());
    }

    #[test]
    fn variable_ref_management() {
        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        let r1 = server.alloc_var_ref();
        let r2 = server.alloc_var_ref();
        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
        assert_eq!(server.next_var_ref, 3);
    }

    #[test]
    fn maybe_create_child_ref_formats_struct_values() {
        use crate::variables::{MemberInfo, TypeInfo, TypeKind};

        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        // Build a struct variable: { x: i32, y: i32 }
        let var = Variable {
            name: "point".into(),
            type_info: TypeInfo {
                name: "Point".into(),
                byte_size: 8,
                kind: TypeKind::Struct(vec![
                    MemberInfo {
                        name: "x".into(),
                        type_info: TypeInfo {
                            name: "i32".into(),
                            byte_size: 4,
                            kind: TypeKind::SignedInt,
                        },
                        offset: 0,
                    },
                    MemberInfo {
                        name: "y".into(),
                        type_info: TypeInfo {
                            name: "i32".into(),
                            byte_size: 4,
                            kind: TypeKind::SignedInt,
                        },
                        offset: 4,
                    },
                ]),
            },
            location_expr: vec![],
        };

        // Raw data: x=42, y=-7
        let mut data = Vec::new();
        data.extend_from_slice(&42i32.to_le_bytes());
        data.extend_from_slice(&(-7i32).to_le_bytes());

        let r = server.maybe_create_child_ref(&var, &data);
        assert!(r > 0, "should allocate a variable reference");

        // Verify children have actual values, not <TypeName> placeholders
        if let Some(VariableScope::Children(children)) = server.variable_refs.get(&r) {
            assert_eq!(children.len(), 2);
            assert_eq!(children[0].0, "x");
            assert_eq!(children[0].1, "42");
            assert_eq!(children[1].0, "y");
            assert_eq!(children[1].1, "-7");
        } else {
            panic!("expected Children variant");
        }
    }

    #[test]
    fn maybe_create_child_ref_formats_enum_active_variant() {
        use crate::variables::{EnumVariant, MemberInfo, TypeInfo, TypeKind};

        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        // Option<i32> = Some(42)
        // Layout: [discriminant:1][padding:3][value:4]
        let var = Variable {
            name: "opt".into(),
            type_info: TypeInfo {
                name: "Option<i32>".into(),
                byte_size: 8,
                kind: TypeKind::Enum {
                    discriminant: Some(Box::new(MemberInfo {
                        name: "discriminant".into(),
                        type_info: TypeInfo {
                            name: "u8".into(),
                            byte_size: 1,
                            kind: TypeKind::UnsignedInt,
                        },
                        offset: 0,
                    })),
                    variants: vec![
                        EnumVariant {
                            discr_value: Some(0),
                            name: "None".into(),
                            members: vec![],
                        },
                        EnumVariant {
                            discr_value: Some(1),
                            name: "Some".into(),
                            members: vec![MemberInfo {
                                name: "Some".into(),
                                type_info: TypeInfo {
                                    name: "i32".into(),
                                    byte_size: 4,
                                    kind: TypeKind::Struct(vec![MemberInfo {
                                        name: "__0".into(),
                                        type_info: TypeInfo {
                                            name: "i32".into(),
                                            byte_size: 4,
                                            kind: TypeKind::SignedInt,
                                        },
                                        offset: 0,
                                    }]),
                                },
                                offset: 4,
                            }],
                        },
                    ],
                },
            },
            location_expr: vec![],
        };

        // Some(42): discriminant=1 at byte 0, value=42 at bytes 4..8
        let mut data = vec![0u8; 8];
        data[0] = 1;
        data[4..8].copy_from_slice(&42i32.to_le_bytes());

        let r = server.maybe_create_child_ref(&var, &data);
        assert!(r > 0, "Some variant should have children");

        if let Some(VariableScope::Children(children)) = server.variable_refs.get(&r) {
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].0, "__0");
            assert_eq!(children[0].1, "42");
        } else {
            panic!("expected Children variant");
        }

        // None variant should have no children (ref = 0)
        data[0] = 0;
        let r = server.maybe_create_child_ref(&var, &data);
        assert_eq!(r, 0, "None variant should have no children");
    }

    #[test]
    fn maybe_create_child_ref_no_data_fallback() {
        use crate::variables::{MemberInfo, TypeInfo, TypeKind};

        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        let var = Variable {
            name: "point".into(),
            type_info: TypeInfo {
                name: "Point".into(),
                byte_size: 8,
                kind: TypeKind::Struct(vec![MemberInfo {
                    name: "x".into(),
                    type_info: TypeInfo {
                        name: "i32".into(),
                        byte_size: 4,
                        kind: TypeKind::SignedInt,
                    },
                    offset: 0,
                }]),
            },
            location_expr: vec![],
        };

        // Empty data: should fall back to <TypeName>
        let r = server.maybe_create_child_ref(&var, &[]);
        assert!(r > 0);
        if let Some(VariableScope::Children(children)) = server.variable_refs.get(&r) {
            assert_eq!(children[0].1, "<i32>");
        } else {
            panic!("expected Children variant");
        }
    }

    #[test]
    fn write_memory_address_offset_calculation() {
        // Positive offset.
        let addr = parse_address("0x1000").unwrap();
        let offset: i64 = 0x10;
        let start = addr + offset as u64;
        assert_eq!(start, 0x1010);

        // Negative offset.
        let offset: i64 = -0x10;
        let start = addr.saturating_sub((-offset) as u64);
        assert_eq!(start, 0x0FF0);

        // Base64 decode round-trip.
        use base64::Engine;
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn data_breakpoint_access_type_mapping() {
        use dap::types::DataBreakpointAccessType;

        // DAP Write -> WatchpointType::Write
        let wp = match DataBreakpointAccessType::Write {
            DataBreakpointAccessType::Write => WatchpointType::Write,
            DataBreakpointAccessType::Read => WatchpointType::ReadWrite,
            DataBreakpointAccessType::ReadWrite => WatchpointType::ReadWrite,
        };
        assert!(matches!(wp, WatchpointType::Write));

        // DAP Read -> WatchpointType::ReadWrite (x86_64 only supports RW, not R-only)
        let wp = match DataBreakpointAccessType::Read {
            DataBreakpointAccessType::Write => WatchpointType::Write,
            DataBreakpointAccessType::Read => WatchpointType::ReadWrite,
            DataBreakpointAccessType::ReadWrite => WatchpointType::ReadWrite,
        };
        assert!(matches!(wp, WatchpointType::ReadWrite));

        // DAP ReadWrite -> WatchpointType::ReadWrite
        let wp = match DataBreakpointAccessType::ReadWrite {
            DataBreakpointAccessType::Write => WatchpointType::Write,
            DataBreakpointAccessType::Read => WatchpointType::ReadWrite,
            DataBreakpointAccessType::ReadWrite => WatchpointType::ReadWrite,
        };
        assert!(matches!(wp, WatchpointType::ReadWrite));
    }

    #[test]
    fn instruction_breakpoint_offset_calculation() {
        // No offset.
        let addr = parse_address("0x401000").unwrap();
        let offset: i64 = 0;
        let start = addr + offset as u64;
        assert_eq!(start, 0x401000);

        // Positive offset.
        let addr = parse_address("0x401000").unwrap();
        let offset: i64 = 5;
        let start = addr + offset as u64;
        assert_eq!(start, 0x401005);

        // Negative offset.
        let addr = parse_address("0x401000").unwrap();
        let offset: i64 = -16;
        let start = addr.saturating_sub((-offset) as u64);
        assert_eq!(start, 0x400FF0);
    }

    #[test]
    fn deferred_breakpoints_stored_when_no_target() {
        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let mut server = DapServer::new(input, output);

        // No target set, so breakpoints should be deferred.
        assert!(server.target.is_none());

        server.deferred_source_bps.push(DeferredSourceBreakpoint {
            file: "/src/main.rs".into(),
            line: 42,
            condition: None,
        });
        server.deferred_source_bps.push(DeferredSourceBreakpoint {
            file: "/src/main.rs".into(),
            line: 100,
            condition: Some("x > 5".into()),
        });
        server.deferred_fn_bps.push(DeferredFunctionBreakpoint {
            name: "main".into(),
            condition: None,
        });

        assert_eq!(server.deferred_source_bps.len(), 2);
        assert_eq!(server.deferred_source_bps[0].line, 42);
        assert!(server.deferred_source_bps[0].condition.is_none());
        assert_eq!(server.deferred_source_bps[1].line, 100);
        assert_eq!(
            server.deferred_source_bps[1].condition.as_deref(),
            Some("x > 5")
        );
        assert_eq!(server.deferred_fn_bps.len(), 1);
        assert_eq!(server.deferred_fn_bps[0].name, "main");
    }

    #[test]
    fn new_fields_initialized_empty() {
        let input = BufReader::new(std::io::empty());
        let output = BufWriter::new(std::io::sink());
        let server = DapServer::new(input, output);

        assert!(server.data_breakpoints.is_empty());
        assert!(server.deferred_source_bps.is_empty());
        assert!(server.deferred_fn_bps.is_empty());
        assert!(server.instruction_breakpoints.is_empty());
        assert_eq!(server.last_emitted_event, 0);
    }

    #[test]
    fn format_checksec_output() {
        let result = ChecksecResult {
            relro: SecurityStatus::Full,
            canary: true,
            nx: true,
            pie: true,
            fortify: false,
            rpath: false,
            runpath: false,
        };
        let output = format_checksec(&result, "/usr/bin/test");
        assert!(output.starts_with("[Security] checksec: /usr/bin/test"));
        assert!(output.contains("RELRO:    Full"));
        assert!(output.contains("Canary:   Yes"));
        assert!(output.contains("NX:       Yes"));
        assert!(output.contains("PIE:      Yes"));
        assert!(output.contains("Fortify:  No"));
        assert!(output.contains("RPATH:    No"));
        assert!(output.contains("RUNPATH:  No"));
    }

    #[test]
    fn format_checksec_partial_relro() {
        let result = ChecksecResult {
            relro: SecurityStatus::Partial,
            canary: false,
            nx: false,
            pie: false,
            fortify: false,
            rpath: true,
            runpath: true,
        };
        let output = format_checksec(&result, "/tmp/vuln");
        assert!(output.contains("RELRO:    Partial"));
        assert!(output.contains("Canary:   No"));
        assert!(output.contains("RPATH:    Yes"));
        assert!(output.contains("RUNPATH:  Yes"));
    }

    #[test]
    fn format_antidebug_output() {
        let findings = vec![
            antidebug::AntiDebugFinding {
                technique: antidebug::AntiDebugTechnique::PtraceTraceme,
                addr: 0x401234,
                description: "ptrace(TRACEME) call detected".into(),
            },
            antidebug::AntiDebugFinding {
                technique: antidebug::AntiDebugTechnique::TimingCheck,
                addr: 0,
                description: "clock_gettime import found".into(),
            },
        ];
        let output = format_antidebug(&findings);
        assert!(output.starts_with("[Security] anti-debug techniques detected (2):"));
        assert!(output.contains("ptrace(TRACEME) at 0x401234:"));
        assert!(output.contains("timing check: clock_gettime import found"));
        // addr=0 should not show "at 0x0"
        assert!(!output.contains("at 0x0"));
    }
}
