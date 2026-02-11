//! x86_64 register access via ptrace.
//!
//! Corresponds to sdb's registers.hpp/cpp and book Ch.5-6 (Registers).
//! Uses a table-driven design inspired by sdb's register_info.

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::error::{Error, Result};

/// Register type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterType {
    GeneralPurpose,
    InstructionPointer,
    Flags,
    Segment,
}

/// Metadata for a single register.
#[derive(Debug, Clone, Copy)]
pub struct RegisterInfo {
    pub name: &'static str,
    pub dwarf_id: i32,
    pub reg_type: RegisterType,
}

/// x86_64 register table.
///
/// DWARF register numbers follow the System V AMD64 ABI.
pub const REGISTERS: &[RegisterInfo] = &[
    RegisterInfo { name: "rax",    dwarf_id: 0,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rdx",    dwarf_id: 1,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rcx",    dwarf_id: 2,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rbx",    dwarf_id: 3,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rsi",    dwarf_id: 4,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rdi",    dwarf_id: 5,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rbp",    dwarf_id: 6,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rsp",    dwarf_id: 7,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r8",     dwarf_id: 8,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r9",     dwarf_id: 9,  reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r10",    dwarf_id: 10, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r11",    dwarf_id: 11, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r12",    dwarf_id: 12, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r13",    dwarf_id: 13, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r14",    dwarf_id: 14, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "r15",    dwarf_id: 15, reg_type: RegisterType::GeneralPurpose },
    RegisterInfo { name: "rip",    dwarf_id: 16, reg_type: RegisterType::InstructionPointer },
    RegisterInfo { name: "rflags", dwarf_id: 49, reg_type: RegisterType::Flags },
    RegisterInfo { name: "cs",     dwarf_id: 51, reg_type: RegisterType::Segment },
    RegisterInfo { name: "ss",     dwarf_id: 52, reg_type: RegisterType::Segment },
    RegisterInfo { name: "orig_rax", dwarf_id: -1, reg_type: RegisterType::GeneralPurpose },
];

/// Snapshot of all x86_64 general-purpose registers.
///
/// Wraps libc::user_regs_struct with named accessors.
pub struct Registers {
    regs: libc::user_regs_struct,
}

impl Registers {
    /// Read all registers from a stopped tracee.
    pub fn read(pid: Pid) -> Result<Self> {
        let regs = ptrace::getregs(pid)?;
        Ok(Registers { regs })
    }

    /// Write all registers back to the tracee.
    pub fn write(&self, pid: Pid) -> Result<()> {
        ptrace::setregs(pid, self.regs)?;
        Ok(())
    }

    /// Get a register value by name.
    pub fn get(&self, name: &str) -> Result<u64> {
        match name {
            "rax" => Ok(self.regs.rax),
            "rbx" => Ok(self.regs.rbx),
            "rcx" => Ok(self.regs.rcx),
            "rdx" => Ok(self.regs.rdx),
            "rsi" => Ok(self.regs.rsi),
            "rdi" => Ok(self.regs.rdi),
            "rbp" => Ok(self.regs.rbp),
            "rsp" => Ok(self.regs.rsp),
            "r8" => Ok(self.regs.r8),
            "r9" => Ok(self.regs.r9),
            "r10" => Ok(self.regs.r10),
            "r11" => Ok(self.regs.r11),
            "r12" => Ok(self.regs.r12),
            "r13" => Ok(self.regs.r13),
            "r14" => Ok(self.regs.r14),
            "r15" => Ok(self.regs.r15),
            "rip" => Ok(self.regs.rip),
            "rflags" | "eflags" => Ok(self.regs.eflags),
            "cs" => Ok(self.regs.cs),
            "ss" => Ok(self.regs.ss),
            "orig_rax" => Ok(self.regs.orig_rax),
            _ => Err(Error::Register(format!("unknown register: {}", name))),
        }
    }

    /// Set a register value by name.
    pub fn set(&mut self, name: &str, value: u64) -> Result<()> {
        match name {
            "rax" => self.regs.rax = value,
            "rbx" => self.regs.rbx = value,
            "rcx" => self.regs.rcx = value,
            "rdx" => self.regs.rdx = value,
            "rsi" => self.regs.rsi = value,
            "rdi" => self.regs.rdi = value,
            "rbp" => self.regs.rbp = value,
            "rsp" => self.regs.rsp = value,
            "r8" => self.regs.r8 = value,
            "r9" => self.regs.r9 = value,
            "r10" => self.regs.r10 = value,
            "r11" => self.regs.r11 = value,
            "r12" => self.regs.r12 = value,
            "r13" => self.regs.r13 = value,
            "r14" => self.regs.r14 = value,
            "r15" => self.regs.r15 = value,
            "rip" => self.regs.rip = value,
            "rflags" | "eflags" => self.regs.eflags = value,
            "cs" => self.regs.cs = value,
            "ss" => self.regs.ss = value,
            _ => return Err(Error::Register(format!("unknown register: {}", name))),
        }
        Ok(())
    }

    /// Get the instruction pointer.
    pub fn pc(&self) -> u64 {
        self.regs.rip
    }

    /// Set the instruction pointer.
    pub fn set_pc(&mut self, addr: u64) {
        self.regs.rip = addr;
    }

    /// Get the raw libc struct.
    pub fn raw(&self) -> &libc::user_regs_struct {
        &self.regs
    }

    /// Get a register value by DWARF register number.
    pub fn get_by_dwarf_id(&self, dwarf_id: i32) -> Result<u64> {
        let info = REGISTERS
            .iter()
            .find(|r| r.dwarf_id == dwarf_id)
            .ok_or_else(|| Error::Register(format!("unknown DWARF reg: {}", dwarf_id)))?;
        self.get(info.name)
    }

    /// Iterate over all register name-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        REGISTERS.iter().filter_map(move |info| {
            self.get(info.name).ok().map(|v| (info.name, v))
        })
    }
}
