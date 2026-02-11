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
