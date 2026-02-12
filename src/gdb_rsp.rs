//! GDB Remote Serial Protocol (RSP) server.
//!
//! Implements a minimal GDB stub so external tools (IDA, Ghidra, radare2, GDB)
//! can connect to rnicro over TCP and control the debuggee.
//!
//! Protocol reference: https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html

use crate::error::Result;

// ── Packet encoding/decoding ────────────────────────────────────────

/// Calculate the GDB RSP checksum for a payload.
pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Encode a response payload into a GDB RSP packet: `$<data>#<checksum>`
pub fn encode_packet(data: &str) -> Vec<u8> {
    let cksum = checksum(data.as_bytes());
    format!("${}#{:02x}", data, cksum).into_bytes()
}

/// Decode a GDB RSP packet from raw bytes.
///
/// Returns the payload if the packet is valid, or None if incomplete/invalid.
/// Expects input starting with '$' and ending with '#XX'.
pub fn decode_packet(raw: &[u8]) -> Option<(String, usize)> {
    let start = raw.iter().position(|&b| b == b'$')?;
    let hash_pos = raw[start..].iter().position(|&b| b == b'#').map(|p| p + start)?;

    if hash_pos + 3 > raw.len() {
        return None; // Incomplete checksum
    }

    let payload = &raw[start + 1..hash_pos];
    let cksum_str = std::str::from_utf8(&raw[hash_pos + 1..hash_pos + 3]).ok()?;
    let expected = u8::from_str_radix(cksum_str, 16).ok()?;
    let actual = checksum(payload);

    if actual != expected {
        return None; // Checksum mismatch
    }

    let payload_str = String::from_utf8_lossy(payload).into_owned();
    Some((payload_str, hash_pos + 3))
}

/// Encode bytes as a hex string.
pub fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex string into bytes.
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).ok()?;
        let b = u8::from_str_radix(s, 16).ok()?;
        bytes.push(b);
    }
    Some(bytes)
}

/// Parse a hex address from a string.
pub fn parse_hex_addr(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

/// x86_64 GDB register order (as expected by GDB's target description).
///
/// GDB expects registers in this specific order for 'g' and 'G' packets.
pub const GDB_X86_64_REGS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
];

// ── Protocol response helpers ────────────────────────────────────

/// Build a stop reply packet for a signal.
pub fn stop_reply(signal: u8) -> String {
    format!("S{:02x}", signal)
}

/// Build an "OK" response.
pub fn ok_response() -> &'static str {
    "OK"
}

/// Build an error response.
pub fn error_response(code: u8) -> String {
    format!("E{:02x}", code)
}

/// Build a qSupported response with our capabilities.
pub fn supported_features() -> String {
    "PacketSize=4096;swbreak+;hwbreak+".to_string()
}

/// Process a GDB RSP command and return the response payload.
///
/// This is the core command dispatcher. The `handler` trait object
/// provides access to the debuggee's state.
pub fn handle_command(cmd: &str, handler: &mut dyn GdbHandler) -> String {
    if cmd.is_empty() {
        return String::new();
    }

    match cmd.as_bytes()[0] {
        b'?' => {
            // Stop reason query
            stop_reply(handler.stop_signal())
        }
        b'g' => {
            // Read all registers
            match handler.read_registers_gdb() {
                Ok(hex) => hex,
                Err(_) => error_response(1),
            }
        }
        b'G' => {
            // Write all registers
            match handler.write_registers_gdb(&cmd[1..]) {
                Ok(()) => ok_response().to_string(),
                Err(_) => error_response(1),
            }
        }
        b'm' => {
            // Read memory: m<addr>,<length>
            if let Some((addr_str, len_str)) = cmd[1..].split_once(',') {
                if let (Some(addr), Some(len)) = (parse_hex_addr(addr_str), parse_hex_addr(len_str))
                {
                    match handler.read_memory(addr, len as usize) {
                        Ok(data) => bytes_to_hex(&data),
                        Err(_) => error_response(1),
                    }
                } else {
                    error_response(1)
                }
            } else {
                error_response(1)
            }
        }
        b'M' => {
            // Write memory: M<addr>,<length>:<hex>
            if let Some((header, hex_data)) = cmd[1..].split_once(':') {
                if let Some((addr_str, _len_str)) = header.split_once(',') {
                    if let Some(addr) = parse_hex_addr(addr_str) {
                        if let Some(data) = hex_to_bytes(hex_data) {
                            match handler.write_memory(addr, &data) {
                                Ok(()) => ok_response().to_string(),
                                Err(_) => error_response(1),
                            }
                        } else {
                            error_response(1)
                        }
                    } else {
                        error_response(1)
                    }
                } else {
                    error_response(1)
                }
            } else {
                error_response(1)
            }
        }
        b'c' => {
            // Continue
            match handler.continue_execution() {
                Ok(sig) => stop_reply(sig),
                Err(_) => error_response(1),
            }
        }
        b's' => {
            // Single step
            match handler.single_step() {
                Ok(sig) => stop_reply(sig),
                Err(_) => error_response(1),
            }
        }
        b'Z' => {
            // Insert breakpoint: Z<type>,<addr>,<kind>
            handle_breakpoint_insert(cmd, handler)
        }
        b'z' => {
            // Remove breakpoint: z<type>,<addr>,<kind>
            handle_breakpoint_remove(cmd, handler)
        }
        b'q' => {
            // Query packets
            if cmd.starts_with("qSupported") {
                supported_features()
            } else if cmd == "qAttached" {
                "1".to_string() // We're attached
            } else if cmd.starts_with("qC") {
                format!("QC{:x}", handler.current_tid())
            } else {
                String::new() // Unsupported query
            }
        }
        b'k' => {
            // Kill
            handler.kill();
            ok_response().to_string()
        }
        b'H' => {
            // Set thread: Hg<tid> or Hc<tid>
            ok_response().to_string()
        }
        b'D' => {
            // Detach
            handler.detach();
            ok_response().to_string()
        }
        _ => String::new(), // Unsupported command
    }
}

fn handle_breakpoint_insert(cmd: &str, handler: &mut dyn GdbHandler) -> String {
    // Z<type>,<addr>,<kind>
    let parts: Vec<&str> = cmd[1..].splitn(3, ',').collect();
    if parts.len() < 2 {
        return error_response(1);
    }
    let bp_type = parts[0];
    let addr = match parse_hex_addr(parts[1]) {
        Some(a) => a,
        None => return error_response(1),
    };

    match bp_type {
        "0" => {
            // Software breakpoint
            match handler.insert_breakpoint(addr) {
                Ok(()) => ok_response().to_string(),
                Err(_) => error_response(1),
            }
        }
        _ => String::new(), // Unsupported breakpoint type
    }
}

fn handle_breakpoint_remove(cmd: &str, handler: &mut dyn GdbHandler) -> String {
    let parts: Vec<&str> = cmd[1..].splitn(3, ',').collect();
    if parts.len() < 2 {
        return error_response(1);
    }
    let bp_type = parts[0];
    let addr = match parse_hex_addr(parts[1]) {
        Some(a) => a,
        None => return error_response(1),
    };

    match bp_type {
        "0" => match handler.remove_breakpoint(addr) {
            Ok(()) => ok_response().to_string(),
            Err(_) => error_response(1),
        },
        _ => String::new(),
    }
}

/// Trait for handling GDB RSP commands.
///
/// Implemented by the Target to provide debuggee access.
pub trait GdbHandler {
    /// Get the signal that caused the current stop.
    fn stop_signal(&self) -> u8;
    /// Get the current thread ID.
    fn current_tid(&self) -> u32;
    /// Read all registers as hex (GDB register order).
    fn read_registers_gdb(&self) -> Result<String>;
    /// Write all registers from hex (GDB register order).
    fn write_registers_gdb(&mut self, hex: &str) -> Result<()>;
    /// Read memory.
    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>>;
    /// Write memory.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<()>;
    /// Continue execution, return the stop signal.
    fn continue_execution(&mut self) -> Result<u8>;
    /// Single step, return the stop signal.
    fn single_step(&mut self) -> Result<u8>;
    /// Insert a software breakpoint.
    fn insert_breakpoint(&mut self, addr: u64) -> Result<()>;
    /// Remove a software breakpoint.
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()>;
    /// Kill the debuggee.
    fn kill(&mut self);
    /// Detach from the debuggee.
    fn detach(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_basic() {
        assert_eq!(checksum(b"OK"), b'O'.wrapping_add(b'K'));
    }

    #[test]
    fn encode_ok() {
        let packet = encode_packet("OK");
        let s = String::from_utf8(packet).unwrap();
        assert!(s.starts_with("$OK#"));
        assert_eq!(s.len(), 6); // $OK#XX
    }

    #[test]
    fn decode_valid_packet() {
        let packet = encode_packet("S05");
        let (payload, consumed) = decode_packet(&packet).unwrap();
        assert_eq!(payload, "S05");
        assert_eq!(consumed, packet.len());
    }

    #[test]
    fn decode_invalid_checksum() {
        let result = decode_packet(b"$OK#00");
        assert!(result.is_none());
    }

    #[test]
    fn decode_incomplete() {
        let result = decode_packet(b"$OK#");
        assert!(result.is_none());
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = bytes_to_hex(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_to_bytes_odd_length() {
        assert!(hex_to_bytes("abc").is_none());
    }

    #[test]
    fn parse_hex_addr_works() {
        assert_eq!(parse_hex_addr("401000"), Some(0x401000));
        assert_eq!(parse_hex_addr("0"), Some(0));
        assert!(parse_hex_addr("xyz").is_none());
    }

    #[test]
    fn stop_reply_format() {
        assert_eq!(stop_reply(5), "S05");
        assert_eq!(stop_reply(11), "S0b");
    }

    #[test]
    fn supported_features_format() {
        let feat = supported_features();
        assert!(feat.contains("PacketSize="));
        assert!(feat.contains("swbreak+"));
    }

    struct MockHandler {
        signal: u8,
    }

    impl GdbHandler for MockHandler {
        fn stop_signal(&self) -> u8 { self.signal }
        fn current_tid(&self) -> u32 { 1234 }
        fn read_registers_gdb(&self) -> Result<String> {
            Ok("0".repeat(24 * 16)) // 24 regs * 8 bytes * 2 hex chars
        }
        fn write_registers_gdb(&mut self, _hex: &str) -> Result<()> { Ok(()) }
        fn read_memory(&self, _addr: u64, len: usize) -> Result<Vec<u8>> {
            Ok(vec![0x90; len])
        }
        fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<()> { Ok(()) }
        fn continue_execution(&mut self) -> Result<u8> { Ok(5) }
        fn single_step(&mut self) -> Result<u8> { Ok(5) }
        fn insert_breakpoint(&mut self, _addr: u64) -> Result<()> { Ok(()) }
        fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> { Ok(()) }
        fn kill(&mut self) {}
        fn detach(&mut self) {}
    }

    #[test]
    fn handle_stop_reason() {
        let mut h = MockHandler { signal: 5 };
        let resp = handle_command("?", &mut h);
        assert_eq!(resp, "S05");
    }

    #[test]
    fn handle_read_memory() {
        let mut h = MockHandler { signal: 5 };
        let resp = handle_command("m401000,10", &mut h);
        assert_eq!(resp.len(), 32); // 16 bytes * 2 hex chars
        assert!(resp.chars().all(|c| c == '9' || c == '0'));
    }

    #[test]
    fn handle_continue() {
        let mut h = MockHandler { signal: 5 };
        let resp = handle_command("c", &mut h);
        assert_eq!(resp, "S05");
    }

    #[test]
    fn handle_breakpoint_insert_remove() {
        let mut h = MockHandler { signal: 5 };
        assert_eq!(handle_command("Z0,401000,1", &mut h), "OK");
        assert_eq!(handle_command("z0,401000,1", &mut h), "OK");
    }

    #[test]
    fn handle_qsupported() {
        let mut h = MockHandler { signal: 5 };
        let resp = handle_command("qSupported:multiprocess+", &mut h);
        assert!(resp.contains("PacketSize="));
    }
}
