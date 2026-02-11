//! ELF binary loading and symbol resolution.
//!
//! Corresponds to sdb's elf.hpp/cpp and book Ch.9 (ELF and DWARF).
//! Memory-maps the ELF binary and provides symbol lookup
//! for mapping addresses to function names.

use std::path::Path;

use memmap2::Mmap;
use object::{Object, ObjectSymbol, SymbolKind};

use crate::error::{Error, Result};
use crate::types::VirtAddr;

/// Classification of ELF symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    /// Code / function symbol.
    Function,
    /// Data / object symbol.
    Data,
    /// Other symbol types.
    Other,
}

/// A resolved symbol from the ELF file.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name (may be mangled).
    pub name: String,
    /// Virtual address of the symbol.
    pub addr: VirtAddr,
    /// Size of the symbol in bytes (0 if unknown).
    pub size: u64,
    /// Symbol classification.
    pub kind: SymbolType,
}

/// A loaded ELF binary with symbol table access.
pub struct ElfFile {
    _mmap: Mmap,
    symbols: Vec<Symbol>,
}

impl ElfFile {
    /// Load an ELF binary from disk via memory mapping.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Other(format!("open ELF '{}': {}", path.display(), e)))?;
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| Error::Other(format!("mmap ELF: {}", e)))?;
        let obj = object::File::parse(&*mmap)
            .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

        let mut symbols = Vec::new();
        for sym in obj.symbols() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() && sym.address() != 0 {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        addr: VirtAddr(sym.address()),
                        size: sym.size(),
                        kind: match sym.kind() {
                            SymbolKind::Text => SymbolType::Function,
                            SymbolKind::Data => SymbolType::Data,
                            _ => SymbolType::Other,
                        },
                    });
                }
            }
        }

        // Also include dynamic symbols
        for sym in obj.dynamic_symbols() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() && sym.address() != 0 {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        addr: VirtAddr(sym.address()),
                        size: sym.size(),
                        kind: match sym.kind() {
                            SymbolKind::Text => SymbolType::Function,
                            SymbolKind::Data => SymbolType::Data,
                            _ => SymbolType::Other,
                        },
                    });
                }
            }
        }

        // Sort by address for efficient lookup
        symbols.sort_by_key(|s| s.addr);

        Ok(ElfFile { _mmap: mmap, symbols })
    }

    /// Find a symbol by exact name match.
    pub fn find_symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Find the symbol containing the given address.
    pub fn find_symbol_at(&self, addr: VirtAddr) -> Option<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.size > 0)
            .find(|s| addr.addr() >= s.addr.addr() && addr.addr() < s.addr.addr() + s.size)
    }

    /// Iterate over all function symbols with nonzero size.
    pub fn functions(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymbolType::Function && s.size > 0)
    }

    /// Get all symbols.
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a test ElfFile with pre-built symbol data (no real mmap needed).
    fn test_elf(symbols: Vec<Symbol>) -> ElfFile {
        // Create a temp file so we can mmap it
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"dummy").unwrap();
        tmp.flush().unwrap();
        let mmap = unsafe { Mmap::map(tmp.as_file()).unwrap() };
        ElfFile { _mmap: mmap, symbols }
    }

    #[test]
    fn symbol_type_equality() {
        assert_eq!(SymbolType::Function, SymbolType::Function);
        assert_ne!(SymbolType::Function, SymbolType::Data);
    }

    #[test]
    fn symbol_sorting() {
        let syms = vec![
            Symbol {
                name: "b".into(),
                addr: VirtAddr(0x2000),
                size: 10,
                kind: SymbolType::Function,
            },
            Symbol {
                name: "a".into(),
                addr: VirtAddr(0x1000),
                size: 20,
                kind: SymbolType::Function,
            },
        ];
        let mut sorted = syms.clone();
        sorted.sort_by_key(|s| s.addr);
        assert_eq!(sorted[0].name, "a");
        assert_eq!(sorted[1].name, "b");
    }

    #[test]
    fn find_symbol_at_address() {
        let elf = test_elf(vec![
            Symbol {
                name: "func_a".into(),
                addr: VirtAddr(0x1000),
                size: 0x100,
                kind: SymbolType::Function,
            },
            Symbol {
                name: "func_b".into(),
                addr: VirtAddr(0x2000),
                size: 0x50,
                kind: SymbolType::Function,
            },
        ]);

        assert_eq!(
            elf.find_symbol_at(VirtAddr(0x1050)).map(|s| &s.name[..]),
            Some("func_a")
        );
        assert_eq!(
            elf.find_symbol_at(VirtAddr(0x2000)).map(|s| &s.name[..]),
            Some("func_b")
        );
        assert!(elf.find_symbol_at(VirtAddr(0x3000)).is_none());
        assert!(elf.find_symbol_at(VirtAddr(0x9999)).is_none());
    }

    #[test]
    fn find_symbol_by_name() {
        let elf = test_elf(vec![Symbol {
            name: "main".into(),
            addr: VirtAddr(0x401000),
            size: 100,
            kind: SymbolType::Function,
        }]);

        assert!(elf.find_symbol("main").is_some());
        assert!(elf.find_symbol("nonexistent").is_none());
    }

    #[test]
    fn functions_iterator() {
        let elf = test_elf(vec![
            Symbol {
                name: "func".into(),
                addr: VirtAddr(0x1000),
                size: 10,
                kind: SymbolType::Function,
            },
            Symbol {
                name: "global_var".into(),
                addr: VirtAddr(0x2000),
                size: 8,
                kind: SymbolType::Data,
            },
            Symbol {
                name: "zero_size_func".into(),
                addr: VirtAddr(0x3000),
                size: 0,
                kind: SymbolType::Function,
            },
        ]);

        let funcs: Vec<_> = elf.functions().collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "func");
    }
}
