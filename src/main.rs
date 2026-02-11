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
            "step" | "stepi" | "si" => cmd_step(target),
            "register" | "reg" | "r" => cmd_register(target, args),
            "breakpoint" | "break" | "b" => cmd_breakpoint(target, args),
            "memory" | "mem" | "x" => cmd_memory(target, args),
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
        Ok(())
    }

    fn cmd_step(target: &mut Target) -> anyhow::Result<()> {
        let reason = target.step_instruction()?;
        print_stop_reason(&reason);
        let regs = target.read_registers()?;
        println!("  rip = {}", format!("0x{:016x}", regs.pc()).cyan());
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
                    println!("usage: breakpoint set <address>");
                    return Ok(());
                }
                let addr = VirtAddr(parse_address(args[1])?);
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

    fn cmd_help() -> anyhow::Result<()> {
        println!("{}", "rnicro - Linux x86_64 debugger".bold());
        println!();
        println!("  {} (c)          resume execution", "continue".bold());
        println!(
            "  {} (si)            single-step one instruction",
            "stepi".bold()
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
        println!("    breakpoint delete <a>  remove a breakpoint");
        println!("    breakpoint list        list all breakpoints");
        println!(
            "  {} (x)            read memory / maps",
            "memory".bold()
        );
        println!("    memory read <addr> [n] hex dump");
        println!("    memory maps            show memory mappings");
        println!("  {} (h)              this help", "help".bold());
        println!("  {} (q)              exit", "quit".bold());
        Ok(())
    }

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

    fn parse_address(s: &str) -> anyhow::Result<u64> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16)
            .map_err(|e| anyhow::anyhow!("invalid address '{}': {}", s, e))
    }
}
