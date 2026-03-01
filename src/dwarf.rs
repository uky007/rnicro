//! DWARF debug information parsing.
//!
//! Corresponds to sdb's dwarf.hpp/cpp and book Ch.9 (ELF and DWARF).
//! Provides line table and function name lookups for source-level debugging,
//! as well as source line to address reverse lookups for breakpoint resolution.
//! Uses `gimli` for low-level DWARF parsing and `addr2line` for
//! high-level address-to-source mapping.

use std::path::Path;
use std::rc::Rc;

use gimli::{EndianRcSlice, Reader, RunTimeEndian};
use object::{Object, ObjectSection};

use crate::error::{Error, Result};
use crate::types::VirtAddr;

/// Reader type backed by reference-counted byte slices.
/// Avoids lifetime issues by owning the section data via `Rc<[u8]>`.
type GimliReader = EndianRcSlice<RunTimeEndian>;

/// A source code location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// Source file path (as recorded in DWARF info).
    pub file: String,
    /// Line number (1-indexed, 0 if unknown).
    pub line: u32,
    /// Column number (1-indexed, None if unknown).
    pub column: Option<u32>,
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file, self.line)?;
        if let Some(col) = self.column {
            write!(f, ":{}", col)?;
        }
        Ok(())
    }
}

/// DWARF debug information for a binary.
///
/// Wraps an `addr2line::Context` to provide address-to-source mappings,
/// and retains the raw `gimli::Dwarf` for line program traversal.
pub struct DwarfInfo {
    context: addr2line::Context<GimliReader>,
    dwarf: gimli::Dwarf<GimliReader>,
}

impl DwarfInfo {
    /// Load DWARF information from an ELF binary.
    ///
    /// Reads the file, parses DWARF sections into `Rc`-backed buffers
    /// (so the `DwarfInfo` owns all its data with no lifetime constraints),
    /// and builds an `addr2line::Context` for efficient lookups.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Other(format!("read ELF for DWARF: {}", e)))?;
        let obj = object::File::parse(&*data)
            .map_err(|e| Error::Other(format!("parse ELF for DWARF: {}", e)))?;

        // Load each DWARF section into an Rc-backed slice.
        let load_section =
            |section_id: gimli::SectionId| -> std::result::Result<GimliReader, gimli::Error> {
                let section_data = obj
                    .section_by_name(section_id.name())
                    .and_then(|s| s.data().ok())
                    .unwrap_or(&[]);
                Ok(EndianRcSlice::new(
                    Rc::from(section_data),
                    RunTimeEndian::Little,
                ))
            };

        // Load twice: once for addr2line context, once for raw gimli access.
        let dwarf_for_ctx = gimli::Dwarf::load(load_section)
            .map_err(|e| Error::Other(format!("load DWARF sections: {}", e)))?;
        let dwarf = gimli::Dwarf::load(load_section)
            .map_err(|e| Error::Other(format!("load DWARF sections: {}", e)))?;

        let context = addr2line::Context::from_dwarf(dwarf_for_ctx)
            .map_err(|e| Error::Other(format!("build DWARF context: {}", e)))?;

        Ok(DwarfInfo { context, dwarf })
    }

    /// Find the source location for an instruction address.
    ///
    /// Returns `None` if no DWARF line info covers the address.
    pub fn find_location(&self, addr: VirtAddr) -> Result<Option<SourceLocation>> {
        let loc = self
            .context
            .find_location(addr.addr())
            .map_err(|e| Error::Other(format!("DWARF location lookup: {}", e)))?;
        Ok(loc.map(|l| SourceLocation {
            file: l.file.unwrap_or("??").to_string(),
            line: l.line.unwrap_or(0),
            column: l.column,
        }))
    }

    /// Find the function name for an instruction address.
    ///
    /// Uses DWARF info to resolve the function, handling inlined functions.
    /// Returns the demangled name when possible.
    pub fn find_function(&self, addr: VirtAddr) -> Result<Option<String>> {
        let mut frames = self
            .context
            .find_frames(addr.addr())
            .skip_all_loads()
            .map_err(|e| Error::Other(format!("DWARF frame lookup: {}", e)))?;

        // Get the innermost frame (accounts for inlined functions).
        if let Some(frame) = frames
            .next()
            .map_err(|e| Error::Other(format!("DWARF frame iter: {}", e)))?
        {
            if let Some(func) = frame.function {
                let name = func
                    .demangle()
                    .map(|cow| cow.to_string())
                    .unwrap_or_else(|_| "<unknown>".to_string());
                return Ok(Some(name));
            }
        }

        Ok(None)
    }

    /// Find the address corresponding to a source file and line number.
    ///
    /// Used by the DAP server to resolve `setBreakpoints` requests (file:line -> address).
    /// File paths are matched by suffix to handle the difference between editor
    /// full paths and DWARF relative paths.
    pub fn find_address(&self, file: &str, line: u32) -> Result<Option<VirtAddr>> {
        let target_line = match std::num::NonZeroU64::new(line as u64) {
            Some(l) => l,
            None => return Ok(None),
        };

        let mut units = self.dwarf.units();
        while let Some(header) = units
            .next()
            .map_err(|e| Error::Other(format!("DWARF unit iter: {}", e)))?
        {
            let unit = self
                .dwarf
                .unit(header)
                .map_err(|e| Error::Other(format!("DWARF unit load: {}", e)))?;

            let line_program: gimli::IncompleteLineProgram<GimliReader> =
                match unit.line_program.clone() {
                    Some(lp) => lp,
                    None => continue,
                };

            let (program, sequences) = line_program
                .sequences()
                .map_err(|e| Error::Other(format!("DWARF line program: {}", e)))?;

            for sequence in &sequences {
                let mut sm = program.resume_from(sequence);
                while let Some((_header, row)) = sm
                    .next_row()
                    .map_err(|e| Error::Other(format!("DWARF line row: {}", e)))?
                {
                    if row.line() != Some(target_line) {
                        continue;
                    }

                    if let Some(file_entry) = row.file(program.header()) {
                        let mut path_buf = String::new();
                        if let Some(dir) = file_entry.directory(program.header()) {
                            if let Ok(dir_reader) =
                                self.dwarf.attr_string(&unit, dir)
                            {
                                let dir_slice = dir_reader.to_slice()
                                    .map_err(|e| Error::Other(format!("DWARF dir slice: {}", e)))?;
                                let s = String::from_utf8_lossy(&dir_slice);
                                if !s.is_empty() {
                                    path_buf.push_str(&s);
                                    path_buf.push('/');
                                }
                            }
                        }
                        if let Ok(name_reader) =
                            self.dwarf.attr_string(&unit, file_entry.path_name())
                        {
                            let name_slice = name_reader.to_slice()
                                .map_err(|e| Error::Other(format!("DWARF name slice: {}", e)))?;
                            let s = String::from_utf8_lossy(&name_slice);
                            path_buf.push_str(&s);
                        }

                        // Suffix match: editor sends full path, DWARF may have relative.
                        if file.ends_with(&path_buf) || path_buf.ends_with(file) {
                            return Ok(Some(VirtAddr(row.address())));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_location_display() {
        let loc = SourceLocation {
            file: "src/main.c".into(),
            line: 42,
            column: Some(5),
        };
        assert_eq!(loc.to_string(), "src/main.c:42:5");

        let loc_no_col = SourceLocation {
            file: "src/main.c".into(),
            line: 10,
            column: None,
        };
        assert_eq!(loc_no_col.to_string(), "src/main.c:10");
    }

    #[test]
    fn source_location_equality() {
        let a = SourceLocation {
            file: "a.c".into(),
            line: 1,
            column: None,
        };
        let b = SourceLocation {
            file: "a.c".into(),
            line: 1,
            column: None,
        };
        let c = SourceLocation {
            file: "a.c".into(),
            line: 2,
            column: None,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
