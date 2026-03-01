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
//! Then configure your editor to use it as a debug adapter. For VS Code,
//! add to `.vscode/launch.json`:
//!
//! ```json
//! {
//!     "type": "rnicro",
//!     "request": "launch",
//!     "program": "${workspaceFolder}/target/debug/myapp",
//!     "args": []
//! }
//! ```
//!
//! # Supported DAP commands
//!
//! | Category       | Commands                                                    |
//! |----------------|-------------------------------------------------------------|
//! | Lifecycle      | initialize, launch, attach, configurationDone, disconnect   |
//! | Breakpoints    | setBreakpoints, setFunctionBreakpoints, setExceptionBreakpoints |
//! | Execution      | continue, next (step over), stepIn, stepOut, pause          |
//! | Inspection     | threads, stackTrace, scopes, variables, evaluate            |
//! | Low-level      | disassemble, readMemory                                     |
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

use dap::events::{
    Event, ExitedEventBody, OutputEventBody, StoppedEventBody, ThreadEventBody,
};
use dap::prelude::*;
use dap::requests::Command;
use dap::responses::{Response, ResponseBody};
use dap::types::{
    Breakpoint, Capabilities, DisassembledInstruction, ExceptionBreakpointsFilter, Scope,
    Source, StackFrame, Thread,
};

use crate::disasm::DisasmStyle;
use crate::dwarf::DwarfInfo;
use crate::error::Result;
use crate::target::Target;
use crate::types::{StopReason, VirtAddr};
use crate::variables::{TypeKind, Variable};

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
        Ok(())
    }

    fn handle_set_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetBreakpointsArguments,
    ) -> Result<()> {
        let source_path = args
            .source
            .path
            .as_deref()
            .unwrap_or("")
            .to_string();

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
                    let mut bp_id = self.next_bp_id;
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
                        // No target yet; store for later.
                        self.source_breakpoints
                            .insert((source_path.clone(), line), addr);
                        verified = true;
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
            ResponseBody::SetFunctionBreakpoints(
                dap::responses::SetFunctionBreakpointsResponse {
                    breakpoints: result_bps,
                },
            ),
        );
        Ok(())
    }

    fn handle_set_exception_breakpoints(
        &mut self,
        seq: i64,
        args: &dap::requests::SetExceptionBreakpointsArguments,
    ) -> Result<()> {
        if let Some(ref mut target) = self.target {
            use nix::sys::signal::Signal;
            use crate::target::SignalPolicy;

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

        self.send_ok(seq, ResponseBody::SetExceptionBreakpoints);
        Ok(())
    }

    fn handle_continue(
        &mut self,
        seq: i64,
        _args: &dap::requests::ContinueArguments,
    ) -> Result<()> {
        let target = match self.target.as_mut() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        self.variable_refs.clear();
        self.next_var_ref = 1;

        match target.resume() {
            Ok(reason) => {
                self.send_ok(
                    seq,
                    ResponseBody::Continue(dap::responses::ContinueResponse {
                        all_threads_continued: Some(true),
                    }),
                );
                self.handle_stop_reason(&reason);
            }
            Err(e) => {
                self.send_error(seq, &format!("continue failed: {}", e));
            }
        }
        Ok(())
    }

    fn handle_next(
        &mut self,
        seq: i64,
        _args: &dap::requests::NextArguments,
    ) -> Result<()> {
        self.do_step(seq, "next")
    }

    fn handle_step_in(
        &mut self,
        seq: i64,
        _args: &dap::requests::StepInArguments,
    ) -> Result<()> {
        self.do_step(seq, "stepIn")
    }

    fn handle_step_out(
        &mut self,
        seq: i64,
        _args: &dap::requests::StepOutArguments,
    ) -> Result<()> {
        self.do_step(seq, "stepOut")
    }

    fn do_step(&mut self, seq: i64, kind: &str) -> Result<()> {
        let target = match self.target.as_mut() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        self.variable_refs.clear();
        self.next_var_ref = 1;

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
            }
            Err(e) => {
                self.send_error(seq, &format!("{} failed: {}", kind, e));
            }
        }
        Ok(())
    }

    fn handle_pause(
        &mut self,
        seq: i64,
        _args: &dap::requests::PauseArguments,
    ) -> Result<()> {
        if let Some(ref target) = self.target {
            use nix::sys::signal;
            let _ = signal::kill(target.pid(), signal::Signal::SIGSTOP);
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
        _args: &dap::requests::StackTraceArguments,
    ) -> Result<()> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        match target.backtrace() {
            Ok(frames) => {
                let stack_frames: Vec<StackFrame> = frames
                    .iter()
                    .map(|f| format_stack_frame(f))
                    .collect();
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

    fn handle_scopes(
        &mut self,
        seq: i64,
        args: &dap::requests::ScopesArguments,
    ) -> Result<()> {
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

    fn handle_evaluate(
        &mut self,
        seq: i64,
        args: &dap::requests::EvaluateArguments,
    ) -> Result<()> {
        let target = match self.target.as_ref() {
            Some(t) => t,
            None => {
                self.send_error(seq, "no active debug target");
                return Ok(());
            }
        };

        match target.read_variable(&args.expression) {
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
                self.send_error(seq, &format!("variable '{}' not found", args.expression));
            }
            Err(e) => {
                self.send_error(seq, &format!("evaluate failed: {}", e));
            }
        }
        Ok(())
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

        let addr = parse_address(&args.memory_reference);
        let offset = args.instruction_offset.unwrap_or(0) as i64;
        let count = args.instruction_count as usize;
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
                    ResponseBody::Disassemble(dap::responses::DisassembleResponse {
                        instructions,
                    }),
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

        let addr = parse_address(&args.memory_reference);
        let offset = args.offset.unwrap_or(0) as i64;
        let start = if offset >= 0 {
            addr + offset as u64
        } else {
            addr.saturating_sub((-offset) as u64)
        };
        let count = args.count as usize;

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
                let name = crate::syscall::syscall_name(*number)
                    .unwrap_or("unknown")
                    .to_string();
                self.send_stopped_with_text("exception", &format!("syscall entry: {}", name));
            }
            StopReason::SyscallExit { number, .. } => {
                let name = crate::syscall::syscall_name(*number)
                    .unwrap_or("unknown")
                    .to_string();
                self.send_stopped_with_text("exception", &format!("syscall exit: {}", name));
            }
            StopReason::Exited(code) => {
                let _ = self.server.send_event(Event::Exited(ExitedEventBody {
                    exit_code: *code as i64,
                }));
                let _ = self.server.send_event(Event::Terminated(None));
            }
            StopReason::Terminated(sig) => {
                let _ = self
                    .server
                    .send_event(Event::Exited(ExitedEventBody { exit_code: -1 }));
                let _ = self.send_output(&format!("terminated by signal: {}", sig));
                let _ = self.server.send_event(Event::Terminated(None));
            }
            StopReason::ThreadCreated(tid) => {
                let _ = self.server.send_event(Event::Thread(ThreadEventBody {
                    reason: dap::types::ThreadEventReason::Started,
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

        let mut result = Vec::new();
        for var in vars {
            let formatted = target
                .read_variable(&var.name)
                .ok()
                .flatten()
                .map(|(_, f)| f)
                .unwrap_or_else(|| "<unavailable>".into());

            let child_ref = self.maybe_create_child_ref(&var);

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

    fn maybe_create_child_ref(&mut self, var: &Variable) -> i64 {
        match &var.type_info.kind {
            TypeKind::Struct(members) if !members.is_empty() => {
                let children: Vec<(String, String, String)> = members
                    .iter()
                    .map(|m| {
                        (
                            m.name.clone(),
                            format!("<{}>", m.type_info.name),
                            m.type_info.name.clone(),
                        )
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
                        (
                            m.name.clone(),
                            format!("<{}>", m.type_info.name),
                            m.type_info.name.clone(),
                        )
                    })
                    .collect();
                let r = self.alloc_var_ref();
                self.variable_refs
                    .insert(r, VariableScope::Children(children));
                r
            }
            TypeKind::Enum { variants, .. } if !variants.is_empty() => {
                let children: Vec<(String, String, String)> = variants
                    .iter()
                    .map(|v| {
                        let detail = if v.members.is_empty() {
                            "(unit)".to_string()
                        } else {
                            format!("({} fields)", v.members.len())
                        };
                        (v.name.clone(), detail, "variant".to_string())
                    })
                    .collect();
                let r = self.alloc_var_ref();
                self.variable_refs
                    .insert(r, VariableScope::Children(children));
                r
            }
            _ => 0,
        }
    }

    // ── Source line resolution ─────────────────────────────────────────

    fn resolve_source_line(&self, file: &str, line: u32) -> Option<VirtAddr> {
        self.dwarf.as_ref()?.find_address(file, line).ok()?
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
        name: Some(
            loc.file
                .rsplit('/')
                .next()
                .unwrap_or(&loc.file)
                .to_string(),
        ),
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

/// Parse a hex address string (with optional "0x" prefix) to u64.
fn parse_address(s: &str) -> u64 {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
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
    }
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
            stop_reason_to_stopped_reason(&StopReason::Signal(
                nix::sys::signal::Signal::SIGSEGV
            )),
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
            stop_reason_to_stopped_reason(&StopReason::ThreadCreated(
                nix::unistd::Pid::from_raw(1234)
            )),
            "thread"
        );
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
        assert_eq!(
            sf.instruction_pointer_reference,
            Some("0x401234".into())
        );

        let source = sf.source.unwrap();
        assert_eq!(source.name, Some("main.rs".into()));
        assert_eq!(
            source.path,
            Some("/home/user/project/src/main.rs".into())
        );
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
        assert_eq!(parse_address("0x401000"), 0x401000);
        assert_eq!(parse_address("0X401000"), 0x401000);
        assert_eq!(parse_address("401000"), 0x401000);
        assert_eq!(parse_address("0"), 0);
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
}
