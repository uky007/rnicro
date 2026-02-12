#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rnicro requires Linux (ptrace). This binary was built for a non-Linux target.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use clap::Parser;
    use colored::Colorize;
    use rustyline::DefaultEditor;

    use rnicro::disasm::{self, DisasmStyle};
    use rnicro::target::Target;
    use rnicro::types::{ProcessState, StopReason, VirtAddr};

    #[derive(Parser)]
    #[command(name = "rnicro", about = "A Linux x86_64 debugger")]
    struct Cli {
        /// Program to debug
        program: PathBuf,

        /// Arguments to pass to the program
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    }

    pub fn run() -> anyhow::Result<()> {
        let cli = Cli::parse();

        let args_ref: Vec<&str> = cli.args.iter().map(|s| s.as_str()).collect();
        let mut target = Target::launch(&cli.program, &args_ref)?;

        println!(
            "{} launched process {} ({})",
            "rnicro".bold().cyan(),
            target.pid(),
            cli.program.display()
        );
        if target.has_debug_info() {
            println!("  debug info: {}", "available".green());
        } else {
            println!("  debug info: {}", "not found (stripped binary)".yellow());
        }

        let mut rl = DefaultEditor::new()?;

        loop {
            if target.state() == ProcessState::Exited
                || target.state() == ProcessState::Terminated
            {
                println!("{}", "Process has ended.".yellow());
                break;
            }

            let prompt = format!("{} ", "rnicro>".bold().green());
            let line = match rl.readline(&prompt) {
                Ok(line) => line,
                Err(
                    rustyline::error::ReadlineError::Interrupted
                    | rustyline::error::ReadlineError::Eof,
                ) => {
                    break;
                }
                Err(e) => {
                    eprintln!("readline error: {}", e);
                    break;
                }
            };

            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            rl.add_history_entry(line)?;

            let parts: Vec<&str> = line.split_whitespace().collect();
            let cmd = parts[0];
            let args = &parts[1..];

            if let Err(e) = handle_command(&mut target, cmd, args) {
                eprintln!("{}: {}", "error".red(), e);
            }
        }

        Ok(())
    }

    fn handle_command(target: &mut Target, cmd: &str, args: &[&str]) -> anyhow::Result<()> {
        match cmd {
            "continue" | "c" => cmd_continue(target),
            "stepi" | "si" => cmd_stepi(target),
            "step" | "s" => cmd_step(target),
            "next" | "n" => cmd_next(target),
            "finish" | "fin" => cmd_finish(target),
            "register" | "reg" | "r" => cmd_register(target, args),
            "breakpoint" | "break" | "b" => cmd_breakpoint(target, args),
            "memory" | "mem" | "x" => cmd_memory(target, args),
            "disassemble" | "disas" | "d" => cmd_disassemble(target, args),
            "backtrace" | "bt" => cmd_backtrace(target),
            "watchpoint" | "watch" | "wp" => cmd_watchpoint(target, args),
            "catchpoint" | "catch" => cmd_catchpoint(target, args),
            "signal" | "sig" => cmd_signal(target, args),
            "libs" | "sharedlib" => cmd_libs(target),
            "list" | "l" => cmd_list(target),
            "help" | "h" => cmd_help(),
            "quit" | "q" => std::process::exit(0),
            _ => {
                println!(
                    "unknown command: {}. Type 'help' for available commands.",
                    cmd
                );
                Ok(())
            }
        }
    }

    fn cmd_continue(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.resume()?;
        print_stop_reason(&reason);
        print_location(target);
        Ok(())
    }

    fn cmd_stepi(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.step_instruction()?;
        print_stop_reason(&reason);
        let regs = target.read_registers()?;
        println!("  rip = {}", format!("0x{:016x}", regs.pc()).cyan());
        print_location(target);
        Ok(())
    }

    fn cmd_step(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.step_in()?;
        print_stop_reason(&reason);
        let regs = target.read_registers()?;
        println!("  rip = {}", format!("0x{:016x}", regs.pc()).cyan());
        print_location(target);
        Ok(())
    }

    fn cmd_next(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.step_over()?;
        print_stop_reason(&reason);
        let regs = target.read_registers()?;
        println!("  rip = {}", format!("0x{:016x}", regs.pc()).cyan());
        print_location(target);
        Ok(())
    }

    fn cmd_finish(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.step_out()?;
        print_stop_reason(&reason);
        let regs = target.read_registers()?;
        println!("  rip = {}", format!("0x{:016x}", regs.pc()).cyan());
        print_location(target);
        Ok(())
    }

    fn cmd_register(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        match args.first().copied() {
            Some("read") | Some("r") | None => {
                let regs = target.read_registers()?;
                for (name, value) in regs.iter() {
                    println!(
                        "  {:>8} = {}",
                        name.bold(),
                        format!("0x{:016x}", value).cyan()
                    );
                }
            }
            Some("write") | Some("w") => {
                if args.len() < 3 {
                    println!("usage: register write <name> <value>");
                    return Ok(());
                }
                let name = args[1];
                let value = parse_address(args[2])?;
                let mut regs = target.read_registers()?;
                regs.set(name, value)?;
                target.write_registers(&regs)?;
                println!(
                    "  {} = {}",
                    name.bold(),
                    format!("0x{:016x}", value).cyan()
                );
            }
            Some(sub) => {
                println!("unknown register subcommand: {}", sub);
            }
        }
        Ok(())
    }

    fn cmd_breakpoint(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        match args.first().copied() {
            Some("set") | Some("s") => {
                if args.len() < 2 {
                    println!("usage: breakpoint set <address|symbol>");
                    return Ok(());
                }
                let addr = resolve_address(target, args[1])?;
                let id = target.set_breakpoint(addr)?;
                println!("  breakpoint #{} set at {}", id, addr);
            }
            Some("delete") | Some("d") => {
                if args.len() < 2 {
                    println!("usage: breakpoint delete <address>");
                    return Ok(());
                }
                let addr = VirtAddr(parse_address(args[1])?);
                target.remove_breakpoint(addr)?;
                println!("  breakpoint at {} removed", addr);
            }
            Some("list") | Some("l") | None => {
                let bps = target.list_breakpoints();
                if bps.is_empty() {
                    println!("  no breakpoints set");
                } else {
                    for (i, addr) in bps.iter().enumerate() {
                        println!("  #{}: {}", i + 1, addr);
                    }
                }
            }
            Some(sub) => {
                println!("unknown breakpoint subcommand: {}", sub);
            }
        }
        Ok(())
    }

    fn cmd_memory(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        if args.is_empty() {
            println!("usage: memory read <address> [length]");
            println!("       memory maps");
            return Ok(());
        }

        match args[0] {
            "read" | "r" => {
                if args.len() < 2 {
                    println!("usage: memory read <address> [length]");
                    return Ok(());
                }
                let addr = VirtAddr(parse_address(args[1])?);
                let len: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
                let data = target.read_memory(addr, len)?;
                print_hexdump(addr, &data);
            }
            "maps" | "m" => {
                let maps = target.memory_maps()?;
                println!(
                    "  {:>18} {:>18}  {}  {}",
                    "start".bold(),
                    "end".bold(),
                    "perm".bold(),
                    "pathname".bold()
                );
                for region in &maps {
                    println!(
                        "  {:018x} {:018x}  {}  {}",
                        region.start.addr(),
                        region.end.addr(),
                        region.perms,
                        region.pathname,
                    );
                }
            }
            sub => {
                println!("unknown memory subcommand: {}", sub);
            }
        }
        Ok(())
    }

    fn cmd_disassemble(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        let count: usize = args
            .iter()
            .find(|a| a.starts_with("-c"))
            .and_then(|_| args.iter().find_map(|a| a.parse().ok()))
            .unwrap_or(10);

        let style = if args.contains(&"--att") || args.contains(&"--gas") {
            DisasmStyle::Gas
        } else {
            DisasmStyle::Intel
        };

        let insns = if let Some(addr_str) = args.first().filter(|a| !a.starts_with('-')) {
            let addr = VirtAddr(parse_address(addr_str)?);
            target.disassemble(addr, count, style)?
        } else {
            target.disassemble_at_pc(count, style)?
        };

        print!("{}", disasm::format_disassembly(&insns));
        Ok(())
    }

    fn cmd_watchpoint(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        use rnicro::watchpoint::{WatchpointSize, WatchpointType};

        match args.first().copied() {
            Some("set") | Some("s") => {
                if args.len() < 4 {
                    println!("usage: watchpoint set <address> <write|rw|execute> <size>");
                    println!("  size: 1, 2, 4, or 8 bytes");
                    return Ok(());
                }
                let addr = resolve_address(target, args[1])?;
                let wp_type = match args[2] {
                    "write" | "w" => WatchpointType::Write,
                    "rw" | "readwrite" => WatchpointType::ReadWrite,
                    "execute" | "exec" | "x" => WatchpointType::Execute,
                    other => {
                        println!("unknown watchpoint type: {} (use write|rw|execute)", other);
                        return Ok(());
                    }
                };
                let size_val: usize = args[3].parse().map_err(|_| {
                    anyhow::anyhow!("invalid size: {} (use 1, 2, 4, or 8)", args[3])
                })?;
                let size = WatchpointSize::from_bytes(size_val).ok_or_else(|| {
                    anyhow::anyhow!("invalid size: {} (must be 1, 2, 4, or 8)", size_val)
                })?;
                let id = target.set_watchpoint(addr, wp_type, size)?;
                println!(
                    "  watchpoint #{} set at {} ({}, {} bytes)",
                    id, addr, wp_type, size
                );
            }
            Some("delete") | Some("d") => {
                if args.len() < 2 {
                    println!("usage: watchpoint delete <id>");
                    return Ok(());
                }
                let id: u32 = args[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid id: {}", args[1]))?;
                target.remove_watchpoint(id)?;
                println!("  watchpoint #{} removed", id);
            }
            Some("list") | Some("l") | None => {
                let wps = target.list_watchpoints();
                if wps.is_empty() {
                    println!("  no watchpoints set");
                } else {
                    for wp in &wps {
                        println!(
                            "  #{}: {} ({}, {} bytes) [slot {}]",
                            wp.id, wp.addr, wp.wp_type, wp.size, wp.slot
                        );
                    }
                }
            }
            Some(sub) => {
                println!("unknown watchpoint subcommand: {}", sub);
            }
        }
        Ok(())
    }

    fn cmd_catchpoint(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        match args.first().copied() {
            Some("syscall") | Some("sys") => {
                match args.get(1).copied() {
                    Some("add") | Some("a") => {
                        if args.len() < 3 {
                            println!("usage: catchpoint syscall add <name|number|all>");
                            return Ok(());
                        }
                        if args[2] == "all" {
                            target.set_catch_all_syscalls(true);
                            println!("  catching all syscalls");
                        } else if let Some(num) = rnicro::syscall::number(args[2]) {
                            target.catch_syscall(num);
                            println!("  catching syscall {} ({})", args[2], num);
                        } else if let Ok(num) = args[2].parse::<u64>() {
                            target.catch_syscall(num);
                            let name = rnicro::syscall::name(num).unwrap_or("unknown");
                            println!("  catching syscall {} ({})", name, num);
                        } else {
                            println!("unknown syscall: {}", args[2]);
                        }
                    }
                    Some("remove") | Some("r") => {
                        if args.len() < 3 {
                            println!("usage: catchpoint syscall remove <name|number|all>");
                            return Ok(());
                        }
                        if args[2] == "all" {
                            target.set_catch_all_syscalls(false);
                            println!("  stopped catching all syscalls");
                        } else if let Some(num) = rnicro::syscall::number(args[2]) {
                            target.uncatch_syscall(num);
                            println!("  removed catchpoint for syscall {}", args[2]);
                        } else if let Ok(num) = args[2].parse::<u64>() {
                            target.uncatch_syscall(num);
                            println!("  removed catchpoint for syscall {}", num);
                        }
                    }
                    Some("list") | Some("l") | None => {
                        if target.is_catching_syscalls() {
                            let caught = target.caught_syscalls();
                            if caught.is_empty() {
                                println!("  catching: all syscalls");
                            } else {
                                println!("  caught syscalls:");
                                for &num in caught {
                                    let name = rnicro::syscall::name(num).unwrap_or("unknown");
                                    println!("    {} ({})", name, num);
                                }
                            }
                        } else {
                            println!("  no syscall catchpoints set");
                        }
                    }
                    Some(sub) => println!("unknown catchpoint syscall subcommand: {}", sub),
                }
            }
            None => {
                println!("usage: catchpoint syscall add|remove|list ...");
            }
            Some(sub) => println!("unknown catchpoint type: {}", sub),
        }
        Ok(())
    }

    fn cmd_signal(target: &mut Target, args: &[&str]) -> anyhow::Result<()> {
        use nix::sys::signal::Signal;

        match args.first().copied() {
            Some("handle") | Some("h") => {
                if args.len() < 3 {
                    println!("usage: signal handle <signal> stop|nostop|pass|nopass");
                    return Ok(());
                }
                let sig = parse_signal(args[1])?;
                let mut policy = target.signal_policy(sig);
                for &action in &args[2..] {
                    match action {
                        "stop" => policy.stop = true,
                        "nostop" => policy.stop = false,
                        "pass" => policy.pass = true,
                        "nopass" => policy.pass = false,
                        other => {
                            println!("unknown action: {} (use stop|nostop|pass|nopass)", other);
                            return Ok(());
                        }
                    }
                }
                target.set_signal_policy(sig, policy);
                println!(
                    "  {:?}: stop={}, pass={}",
                    sig, policy.stop, policy.pass
                );
            }
            Some("list") | Some("l") | None => {
                println!("  {:>15}  {}  {}", "signal".bold(), "stop".bold(), "pass".bold());
                let signals = [
                    Signal::SIGHUP, Signal::SIGINT, Signal::SIGQUIT,
                    Signal::SIGILL, Signal::SIGTRAP, Signal::SIGABRT,
                    Signal::SIGBUS, Signal::SIGFPE, Signal::SIGKILL,
                    Signal::SIGUSR1, Signal::SIGSEGV, Signal::SIGUSR2,
                    Signal::SIGPIPE, Signal::SIGALRM, Signal::SIGTERM,
                    Signal::SIGCHLD, Signal::SIGCONT, Signal::SIGSTOP,
                    Signal::SIGTSTP, Signal::SIGTTIN, Signal::SIGTTOU,
                ];
                for sig in &signals {
                    let policy = target.signal_policy(*sig);
                    println!(
                        "  {:>15}  {:<5}  {}",
                        format!("{:?}", sig),
                        if policy.stop { "yes" } else { "no" },
                        if policy.pass { "yes" } else { "no" },
                    );
                }
            }
            Some(sub) => println!("unknown signal subcommand: {}", sub),
        }
        Ok(())
    }

    fn parse_signal(s: &str) -> anyhow::Result<nix::sys::signal::Signal> {
        use nix::sys::signal::Signal;
        let s_upper = s.to_uppercase();
        let name = if s_upper.starts_with("SIG") {
            s_upper.clone()
        } else {
            format!("SIG{}", s_upper)
        };
        match name.as_str() {
            "SIGHUP" => Ok(Signal::SIGHUP),
            "SIGINT" => Ok(Signal::SIGINT),
            "SIGQUIT" => Ok(Signal::SIGQUIT),
            "SIGILL" => Ok(Signal::SIGILL),
            "SIGTRAP" => Ok(Signal::SIGTRAP),
            "SIGABRT" => Ok(Signal::SIGABRT),
            "SIGBUS" => Ok(Signal::SIGBUS),
            "SIGFPE" => Ok(Signal::SIGFPE),
            "SIGKILL" => Ok(Signal::SIGKILL),
            "SIGUSR1" => Ok(Signal::SIGUSR1),
            "SIGSEGV" => Ok(Signal::SIGSEGV),
            "SIGUSR2" => Ok(Signal::SIGUSR2),
            "SIGPIPE" => Ok(Signal::SIGPIPE),
            "SIGALRM" => Ok(Signal::SIGALRM),
            "SIGTERM" => Ok(Signal::SIGTERM),
            "SIGCHLD" => Ok(Signal::SIGCHLD),
            "SIGCONT" => Ok(Signal::SIGCONT),
            "SIGSTOP" => Ok(Signal::SIGSTOP),
            "SIGTSTP" => Ok(Signal::SIGTSTP),
            "SIGTTIN" => Ok(Signal::SIGTTIN),
            "SIGTTOU" => Ok(Signal::SIGTTOU),
            _ => Err(anyhow::anyhow!("unknown signal: {}", s)),
        }
    }

    fn cmd_backtrace(target: &mut Target) -> anyhow::Result<()> {
        match target.backtrace() {
            Ok(frames) => {
                for frame in &frames {
                    print!("  #{:<3} {}", frame.index, format!("0x{:016x}", frame.pc.addr()).cyan());
                    if let Some(func) = &frame.function {
                        print!(" in {}", func.bold());
                    }
                    if let Some(loc) = &frame.location {
                        print!(" at {}", loc);
                    }
                    println!();
                }
                if frames.is_empty() {
                    println!("  {}", "empty backtrace".yellow());
                }
            }
            Err(e) => {
                // Fallback: show at least the current PC
                let regs = target.read_registers()?;
                println!("  #0   {} (unwind failed: {})", format!("0x{:016x}", regs.pc()).cyan(), e);
            }
        }
        Ok(())
    }

    fn cmd_libs(target: &mut Target) -> anyhow::Result<()> {
        match target.shared_libraries() {
            Ok(libs) => {
                println!("  {:>18}  {}", "base address".bold(), "library".bold());
                for lib in &libs {
                    let display_name = if lib.name.is_empty() {
                        "<main executable>".dimmed().to_string()
                    } else {
                        lib.name.clone()
                    };
                    println!(
                        "  {:018x}  {}",
                        lib.base_addr, display_name
                    );
                }
                if libs.is_empty() {
                    println!("  {}", "no shared libraries found (statically linked?)".yellow());
                }
            }
            Err(e) => {
                println!(
                    "  {}: {} (try running 'memory maps' as fallback)",
                    "could not read link_map".yellow(),
                    e
                );
            }
        }
        Ok(())
    }

    fn cmd_list(target: &mut Target) -> anyhow::Result<()> {
        if let Ok(Some(loc)) = target.source_location() {
            println!(
                "  {} {}:{}",
                "at".dimmed(),
                loc.file.bold(),
                loc.line.to_string().bold()
            );
            // Try to read and display the source file
            if let Ok(content) = std::fs::read_to_string(&loc.file) {
                let lines: Vec<&str> = content.lines().collect();
                let line_idx = loc.line as usize;
                let start = line_idx.saturating_sub(4);
                let end = (line_idx + 3).min(lines.len());
                for i in start..end {
                    let marker = if i + 1 == line_idx { ">" } else { " " };
                    let line_num = format!("{:4}", i + 1);
                    if i + 1 == line_idx {
                        println!("  {} {} {}", marker.green().bold(), line_num.green(), lines[i]);
                    } else {
                        println!("  {} {} {}", marker, line_num.dimmed(), lines[i]);
                    }
                }
            }
        } else {
            println!("  {}", "no source information available".yellow());
        }
        if let Ok(Some(func)) = target.current_function() {
            println!("  in {}", func.cyan());
        }
        Ok(())
    }

    fn cmd_help() -> anyhow::Result<()> {
        println!("{}", "rnicro - Linux x86_64 debugger".bold());
        println!();
        println!("  {} (c)          resume execution", "continue".bold());
        println!(
            "  {} (si)            single-step one instruction",
            "stepi".bold()
        );
        println!(
            "  {} (s)              source-level step into",
            "step".bold()
        );
        println!(
            "  {} (n)              source-level step over",
            "next".bold()
        );
        println!(
            "  {} (fin)          step out of current function",
            "finish".bold()
        );
        println!(
            "  {} (r)          read/write registers",
            "register".bold()
        );
        println!("    register read          show all registers");
        println!("    register write <n> <v> set register");
        println!(
            "  {} (b)       manage breakpoints",
            "breakpoint".bold()
        );
        println!("    breakpoint set <addr>  set a breakpoint");
        println!("    breakpoint set <sym>   set at symbol");
        println!("    breakpoint delete <a>  remove a breakpoint");
        println!("    breakpoint list        list all breakpoints");
        println!(
            "  {} (x)            read memory / maps",
            "memory".bold()
        );
        println!("    memory read <addr> [n] hex dump");
        println!("    memory maps            show memory mappings");
        println!(
            "  {} (d)     disassemble instructions",
            "disassemble".bold()
        );
        println!("    disassemble [addr] [N] disassemble N instructions");
        println!("    disassemble --att     use AT&T syntax");
        println!(
            "  {} (bt)         show call stack",
            "backtrace".bold()
        );
        println!(
            "  {} (wp)       hardware watchpoints",
            "watchpoint".bold()
        );
        println!("    watchpoint set <a> <t> <s> set watchpoint (type: write|rw|execute, size: 1|2|4|8)");
        println!("    watchpoint delete <id>     remove watchpoint");
        println!("    watchpoint list            list watchpoints");
        println!(
            "  {} (catch)    manage syscall catchpoints",
            "catchpoint".bold()
        );
        println!("    catch syscall add <name>   catch a syscall");
        println!("    catch syscall add all      catch all syscalls");
        println!("    catch syscall remove <n>   remove catchpoint");
        println!("    catch syscall list         show catchpoints");
        println!(
            "  {} (sig)          configure signal handling",
            "signal".bold()
        );
        println!("    signal handle <sig> <act>  set policy (stop|nostop|pass|nopass)");
        println!("    signal list                show all signal policies");
        println!(
            "  {} (libs)           list loaded shared libraries",
            "sharedlib".bold()
        );
        println!(
            "  {} (l)              show source at current PC",
            "list".bold()
        );
        println!("  {} (h)              this help", "help".bold());
        println!("  {} (q)              exit", "quit".bold());
        Ok(())
    }

    /// Print a stop reason.
    fn print_stop_reason(reason: &StopReason) {
        match reason {
            StopReason::BreakpointHit { addr } => {
                println!("  {} at {}", "breakpoint hit".yellow(), addr);
            }
            StopReason::SingleStep => {
                println!("  {}", "single step".dimmed());
            }
            StopReason::Signal(sig) => {
                println!("  received signal: {:?}", sig);
            }
            StopReason::SyscallEntry { number, args } => {
                let name = rnicro::syscall::name(*number)
                    .unwrap_or("unknown");
                println!(
                    "  {} {}({}) [{}]",
                    "syscall entry:".yellow(),
                    name.bold(),
                    format_syscall_args(args),
                    number,
                );
            }
            StopReason::SyscallExit { number, retval } => {
                let name = rnicro::syscall::name(*number)
                    .unwrap_or("unknown");
                println!(
                    "  {} {}() = {}",
                    "syscall exit:".yellow(),
                    name.bold(),
                    if *retval < 0 {
                        format!("{} ({})", retval, retval).red().to_string()
                    } else {
                        format!("{}", retval)
                    },
                );
            }
            StopReason::WatchpointHit { slot, addr } => {
                println!(
                    "  {} at {} (slot {})",
                    "watchpoint hit".yellow(),
                    addr,
                    slot,
                );
            }
            StopReason::Exited(code) => {
                println!("  process exited with code {}", code);
            }
            StopReason::Terminated(sig) => {
                println!("  process terminated by signal {:?}", sig);
            }
            StopReason::ThreadCreated(pid) => {
                println!("  new thread created: {}", pid);
            }
        }
    }

    fn format_syscall_args(args: &[u64; 6]) -> String {
        args.iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Print source location and function name (if available).
    fn print_location(target: &Target) {
        if let Ok(Some(loc)) = target.source_location() {
            print!("  at {}", loc.to_string().bold());
            if let Ok(Some(func)) = target.current_function() {
                print!(" in {}", func.cyan());
            }
            println!();
        }
    }

    fn print_hexdump(base: VirtAddr, data: &[u8]) {
        for (i, chunk) in data.chunks(16).enumerate() {
            let addr = base.addr() + (i * 16) as u64;
            print!("  {:016x}  ", addr);
            for (j, byte) in chunk.iter().enumerate() {
                if j == 8 {
                    print!(" ");
                }
                print!("{:02x} ", byte);
            }
            for j in chunk.len()..16 {
                if j == 8 {
                    print!(" ");
                }
                print!("   ");
            }
            print!(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!(".");
                }
            }
            println!("|");
        }
    }

    /// Resolve an address argument that may be a hex address or a symbol name.
    fn resolve_address(target: &Target, s: &str) -> anyhow::Result<VirtAddr> {
        // Try parsing as hex address first
        if let Ok(addr) = parse_address(s) {
            return Ok(VirtAddr(addr));
        }
        // Try symbol lookup
        if let Some(addr) = target.find_symbol(s) {
            return Ok(addr);
        }
        Err(anyhow::anyhow!(
            "'{}' is not a valid address or known symbol",
            s
        ))
    }

    fn parse_address(s: &str) -> anyhow::Result<u64> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16)
            .map_err(|e| anyhow::anyhow!("invalid address '{}': {}", s, e))
    }
}
