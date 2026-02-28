//! Variable and type inspection via DWARF debug information.
//!
//! Corresponds to book Ch.20 (Variables and Types).
//!
//! Reads variable metadata from DWARF DIEs (DW_TAG_variable,
//! DW_TAG_formal_parameter), evaluates location expressions, and
//! formats values based on their types.  Supports C/C++ structs,
//! unions (`DW_TAG_union_type`), and Rust enums (tagged unions via
//! `DW_TAG_variant_part` / `DW_TAG_variant`).

use std::path::Path;
use std::rc::Rc;

use gimli::{
    AttributeValue, DebuggingInformationEntry, DwAt, DwTag, EndianRcSlice, Encoding,
    Reader, RunTimeEndian, Unit, UnitOffset,
};
use object::{Object, ObjectSection};

use crate::error::{Error, Result};

type GimliReader = EndianRcSlice<RunTimeEndian>;

/// A variable found in the debug info.
#[derive(Debug)]
pub struct Variable {
    /// Variable name (from DW_AT_name).
    pub name: String,
    /// Type info.
    pub type_info: TypeInfo,
    /// Location expression (raw DWARF bytes).
    pub location_expr: Vec<u8>,
}

/// Basic type information extracted from DWARF.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// Type name (e.g., "int", "char", struct name).
    pub name: String,
    /// Size in bytes.
    pub byte_size: u64,
    /// Underlying kind.
    pub kind: TypeKind,
}

/// Classification of DWARF types.
#[derive(Debug, Clone)]
pub enum TypeKind {
    /// Signed integer.
    SignedInt,
    /// Unsigned integer.
    UnsignedInt,
    /// Floating point.
    Float,
    /// Boolean.
    Bool,
    /// Character.
    Char,
    /// Pointer to another type.
    Pointer(Box<TypeInfo>),
    /// Array of another type.
    Array {
        element: Box<TypeInfo>,
        count: Option<u64>,
    },
    /// Struct or class.
    Struct(Vec<MemberInfo>),
    /// Union type.
    Union(Vec<MemberInfo>),
    /// Rust enum (tagged union via DWARF variant parts).
    Enum {
        discriminant: Option<Box<MemberInfo>>,
        variants: Vec<EnumVariant>,
    },
    /// Unknown / not yet handled.
    Unknown,
}

/// A struct/class member.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub name: String,
    pub type_info: TypeInfo,
    pub offset: u64,
}

/// A variant of a Rust enum (from DWARF `DW_TAG_variant`).
#[derive(Debug, Clone)]
pub struct EnumVariant {
    /// Discriminant value that selects this variant (`None` for default).
    pub discr_value: Option<u64>,
    /// Variant name.
    pub name: String,
    /// Members (fields) of this variant.
    pub members: Vec<MemberInfo>,
}

/// DWARF variable reader.
///
/// Parses `.debug_info` to enumerate variables and their types.
pub struct VariableReader {
    dwarf: gimli::Dwarf<GimliReader>,
}

impl VariableReader {
    /// Load DWARF info for variable reading.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Other(format!("read ELF: {}", e)))?;
        let obj = object::File::parse(&*data)
            .map_err(|e| Error::Other(format!("parse ELF: {}", e)))?;

        let dwarf = gimli::Dwarf::load(
            |section_id| -> std::result::Result<GimliReader, gimli::Error> {
                let section_data = obj
                    .section_by_name(section_id.name())
                    .and_then(|s| s.data().ok())
                    .unwrap_or(&[]);
                Ok(EndianRcSlice::new(
                    Rc::from(section_data),
                    RunTimeEndian::Little,
                ))
            },
        )
        .map_err(|e| Error::Other(format!("load DWARF: {}", e)))?;

        Ok(VariableReader { dwarf })
    }

    /// Find all variables visible at a given PC address.
    pub fn find_variables_at(&self, pc: u64) -> Result<Vec<Variable>> {
        let mut vars = Vec::new();
        let mut units = self.dwarf.units();

        while let Some(header) =
            units.next().map_err(|e| Error::Other(format!("DWARF units: {}", e)))?
        {
            let unit = self
                .dwarf
                .unit(header)
                .map_err(|e| Error::Other(format!("DWARF unit: {}", e)))?;
            let encoding = unit.encoding();

            // Check if this unit contains the PC
            if !self.unit_contains_pc(&unit, pc)? {
                continue;
            }

            // Walk the DIE tree looking for variables in scope
            let mut entries = unit.entries();
            let mut depth: isize = 0;
            let mut in_scope = false;

            while let Some((delta, entry)) =
                entries.next_dfs().map_err(|e| Error::Other(format!("DIE iter: {}", e)))?
            {
                depth += delta;

                match entry.tag() {
                    DwTag(0x2e) /* DW_TAG_subprogram */ | DwTag(0x0b) /* DW_TAG_lexical_block */ => {
                        in_scope = self.die_contains_pc(entry, &unit, pc)?;
                    }
                    DwTag(0x34) /* DW_TAG_variable */ | DwTag(0x05) /* DW_TAG_formal_parameter */ => {
                        if in_scope || depth <= 1 {
                            if let Some(var) = self.extract_variable(entry, &unit, encoding)? {
                                vars.push(var);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(vars)
    }

    /// Find a specific variable by name at a given PC.
    pub fn find_variable(&self, pc: u64, name: &str) -> Result<Option<Variable>> {
        let vars = self.find_variables_at(pc)?;
        Ok(vars.into_iter().find(|v| v.name == name))
    }

    /// Check if a compile unit contains a given PC.
    fn unit_contains_pc(&self, unit: &Unit<GimliReader>, pc: u64) -> Result<bool> {
        let mut entries = unit.entries();
        if let Some((_, entry)) =
            entries.next_dfs().map_err(|e| Error::Other(format!("CU root: {}", e)))?
        {
            return self.die_contains_pc(entry, unit, pc);
        }
        Ok(false)
    }

    /// Check if a DIE's address range contains a given PC.
    fn die_contains_pc(
        &self,
        entry: &DebuggingInformationEntry<GimliReader>,
        _unit: &Unit<GimliReader>,
        pc: u64,
    ) -> Result<bool> {
        // Try DW_AT_ranges first
        // Note: DW_AT_ranges handling is complex with different DWARF versions.
        // We rely on DW_AT_low_pc/DW_AT_high_pc for now.

        // Fall back to DW_AT_low_pc / DW_AT_high_pc
        let low_pc = match entry
            .attr(DwAt(0x11)) // DW_AT_low_pc
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => match attr.value() {
                AttributeValue::Addr(addr) => addr,
                _ => return Ok(false),
            },
            None => return Ok(false),
        };

        let high_pc = match entry
            .attr(DwAt(0x12)) // DW_AT_high_pc
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => match attr.value() {
                AttributeValue::Addr(addr) => addr,
                AttributeValue::Udata(offset) => low_pc + offset,
                _ => return Ok(false),
            },
            None => return Ok(false),
        };

        Ok(pc >= low_pc && pc < high_pc)
    }

    /// Extract a variable from a DIE.
    fn extract_variable(
        &self,
        entry: &DebuggingInformationEntry<GimliReader>,
        unit: &Unit<GimliReader>,
        encoding: Encoding,
    ) -> Result<Option<Variable>> {
        // Get name
        let name = match entry
            .attr(DwAt(0x03)) // DW_AT_name
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => self.attr_string(&attr, unit)?,
            None => return Ok(None),
        };

        // Get location expression
        let location_expr = match entry
            .attr(DwAt(0x02)) // DW_AT_location
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => match attr.value() {
                AttributeValue::Exprloc(expr) => {
                    let reader = expr.0;
                    reader.to_slice().map_err(|e| Error::Other(format!("expr slice: {}", e)))?.to_vec()
                }
                _ => return Ok(None), // Location lists not supported yet
            },
            None => return Ok(None), // No location = optimized out
        };

        // Get type info
        let type_info = match entry
            .attr(DwAt(0x49)) // DW_AT_type
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => match attr.value() {
                AttributeValue::UnitRef(offset) => {
                    self.resolve_type(unit, offset, encoding, 0)?
                }
                _ => TypeInfo {
                    name: "<unknown>".into(),
                    byte_size: 0,
                    kind: TypeKind::Unknown,
                },
            },
            None => TypeInfo {
                name: "void".into(),
                byte_size: 0,
                kind: TypeKind::Unknown,
            },
        };

        Ok(Some(Variable {
            name,
            type_info,
            location_expr,
        }))
    }

    /// Resolve a type DIE reference into a TypeInfo.
    fn resolve_type(
        &self,
        unit: &Unit<GimliReader>,
        offset: UnitOffset,
        encoding: Encoding,
        depth: usize,
    ) -> Result<TypeInfo> {
        if depth > 20 {
            return Ok(TypeInfo {
                name: "<recursive>".into(),
                byte_size: 0,
                kind: TypeKind::Unknown,
            });
        }

        let entry = unit
            .entry(offset)
            .map_err(|e| Error::Other(format!("type DIE: {}", e)))?;

        let name = entry
            .attr(DwAt(0x03)) // DW_AT_name
            .ok()
            .flatten()
            .and_then(|a| self.attr_string(&a, unit).ok())
            .unwrap_or_default();

        let byte_size = entry
            .attr(DwAt(0x0b)) // DW_AT_byte_size
            .ok()
            .flatten()
            .and_then(|a| a.udata_value())
            .unwrap_or(0);

        let kind = match entry.tag() {
            DwTag(0x24) /* DW_TAG_base_type */ => {
                let dwarf_encoding = entry
                    .attr(DwAt(0x3e)) // DW_AT_encoding
                    .ok()
                    .flatten()
                    .and_then(|a| a.udata_value())
                    .unwrap_or(0);
                match dwarf_encoding {
                    0x01 => TypeKind::Pointer(Box::new(TypeInfo {
                        name: "void".into(),
                        byte_size: 0,
                        kind: TypeKind::Unknown,
                    })), // DW_ATE_address
                    0x02 => TypeKind::Bool,     // DW_ATE_boolean
                    0x04 => TypeKind::Float,    // DW_ATE_float
                    0x05 => TypeKind::SignedInt, // DW_ATE_signed
                    0x06 => TypeKind::Char,     // DW_ATE_signed_char
                    0x07 => TypeKind::UnsignedInt, // DW_ATE_unsigned
                    0x08 => TypeKind::Char,     // DW_ATE_unsigned_char
                    _ => TypeKind::Unknown,
                }
            }
            DwTag(0x0f) /* DW_TAG_pointer_type */ => {
                let pointee = self.resolve_type_ref(&entry, unit, encoding, depth)?;
                TypeKind::Pointer(Box::new(pointee))
            }
            DwTag(0x16) /* DW_TAG_typedef */ | DwTag(0x26) /* DW_TAG_const_type */ | DwTag(0x35) /* DW_TAG_volatile_type */ => {
                // Strip qualifiers / typedefs
                return self.resolve_type_ref(&entry, unit, encoding, depth);
            }
            DwTag(0x01) /* DW_TAG_array_type */ => {
                let element = self.resolve_type_ref(&entry, unit, encoding, depth)?;
                let count = self.array_count(&entry, unit)?;
                TypeKind::Array {
                    element: Box::new(element),
                    count,
                }
            }
            DwTag(0x13) /* DW_TAG_structure_type */ | DwTag(0x02) /* DW_TAG_class_type */ => {
                // Check if this struct contains a DW_TAG_variant_part (Rust enum)
                if self.has_variant_part(unit, offset)? {
                    let (discriminant, variants) =
                        self.resolve_enum_variants(unit, offset, encoding, depth)?;
                    TypeKind::Enum {
                        discriminant,
                        variants,
                    }
                } else {
                    let members = self.struct_members(unit, offset, encoding, depth)?;
                    TypeKind::Struct(members)
                }
            }
            DwTag(0x17) /* DW_TAG_union_type */ => {
                let members = self.struct_members(unit, offset, encoding, depth)?;
                TypeKind::Union(members)
            }
            DwTag(0x04) /* DW_TAG_enumeration_type */ => TypeKind::UnsignedInt,
            DwTag(0x10) /* DW_TAG_reference_type */ | DwTag(0x42) /* DW_TAG_rvalue_reference_type */ => {
                let pointee = self.resolve_type_ref(&entry, unit, encoding, depth)?;
                TypeKind::Pointer(Box::new(pointee))
            }
            _ => TypeKind::Unknown,
        };

        Ok(TypeInfo {
            name,
            byte_size,
            kind,
        })
    }

    /// Resolve the DW_AT_type reference of a DIE.
    fn resolve_type_ref(
        &self,
        entry: &DebuggingInformationEntry<GimliReader>,
        unit: &Unit<GimliReader>,
        encoding: Encoding,
        depth: usize,
    ) -> Result<TypeInfo> {
        match entry
            .attr(DwAt(0x49)) // DW_AT_type
            .map_err(|e| Error::Other(format!("attr: {}", e)))?
        {
            Some(attr) => match attr.value() {
                AttributeValue::UnitRef(offset) => {
                    self.resolve_type(unit, offset, encoding, depth + 1)
                }
                _ => Ok(TypeInfo {
                    name: "void".into(),
                    byte_size: 0,
                    kind: TypeKind::Unknown,
                }),
            },
            None => Ok(TypeInfo {
                name: "void".into(),
                byte_size: 0,
                kind: TypeKind::Unknown,
            }),
        }
    }

    /// Get array element count from DW_TAG_subrange_type child.
    fn array_count(
        &self,
        _entry: &DebuggingInformationEntry<GimliReader>,
        _unit: &Unit<GimliReader>,
    ) -> Result<Option<u64>> {
        // Simplified: would need to iterate children for DW_TAG_subrange_type
        Ok(None)
    }

    /// Get struct members.
    fn struct_members(
        &self,
        unit: &Unit<GimliReader>,
        struct_offset: UnitOffset,
        encoding: Encoding,
        depth: usize,
    ) -> Result<Vec<MemberInfo>> {
        let mut members = Vec::new();
        let mut tree = unit
            .entries_tree(Some(struct_offset))
            .map_err(|e| Error::Other(format!("entries_tree: {}", e)))?;
        let root = tree
            .root()
            .map_err(|e| Error::Other(format!("tree root: {}", e)))?;
        let mut children = root.children();

        while let Some(child) =
            children.next().map_err(|e| Error::Other(format!("child: {}", e)))?
        {
            let entry = child.entry();
            if entry.tag() == DwTag(0x0d) {
                // DW_TAG_member
                let name = entry
                    .attr(DwAt(0x03))
                    .ok()
                    .flatten()
                    .and_then(|a| self.attr_string(&a, unit).ok())
                    .unwrap_or_else(|| "<anon>".into());

                let type_info = self.resolve_type_ref(entry, unit, encoding, depth + 1)?;

                let offset = entry
                    .attr(DwAt(0x38)) // DW_AT_data_member_location
                    .ok()
                    .flatten()
                    .and_then(|a| a.udata_value())
                    .unwrap_or(0);

                members.push(MemberInfo {
                    name,
                    type_info,
                    offset,
                });
            }
        }

        Ok(members)
    }

    /// Check if a struct DIE has a DW_TAG_variant_part child (indicating a Rust enum).
    fn has_variant_part(
        &self,
        unit: &Unit<GimliReader>,
        struct_offset: UnitOffset,
    ) -> Result<bool> {
        let mut tree = unit
            .entries_tree(Some(struct_offset))
            .map_err(|e| Error::Other(format!("entries_tree: {}", e)))?;
        let root = tree
            .root()
            .map_err(|e| Error::Other(format!("tree root: {}", e)))?;
        let mut children = root.children();

        while let Some(child) =
            children.next().map_err(|e| Error::Other(format!("child: {}", e)))?
        {
            if child.entry().tag() == DwTag(0x21) {
                // DW_TAG_variant_part
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Resolve Rust enum variants from DWARF DW_TAG_variant_part.
    ///
    /// Looks for DW_TAG_variant_part children of the struct, extracts
    /// the discriminant member and each DW_TAG_variant with its
    /// DW_AT_discr_value and inner members.
    fn resolve_enum_variants(
        &self,
        unit: &Unit<GimliReader>,
        struct_offset: UnitOffset,
        encoding: Encoding,
        depth: usize,
    ) -> Result<(Option<Box<MemberInfo>>, Vec<EnumVariant>)> {
        let mut discriminant = None;
        let mut variants = Vec::new();

        let mut tree = unit
            .entries_tree(Some(struct_offset))
            .map_err(|e| Error::Other(format!("entries_tree: {}", e)))?;
        let root = tree
            .root()
            .map_err(|e| Error::Other(format!("tree root: {}", e)))?;
        let mut struct_children = root.children();

        while let Some(child) =
            struct_children.next().map_err(|e| Error::Other(format!("child: {}", e)))?
        {
            let entry = child.entry();
            if entry.tag() != DwTag(0x21) {
                // Not DW_TAG_variant_part
                continue;
            }

            // Get discriminant from DW_AT_discr
            if let Some(discr_attr) = entry
                .attr(DwAt(0x15)) // DW_AT_discr
                .map_err(|e| Error::Other(format!("attr: {}", e)))?
            {
                if let AttributeValue::UnitRef(discr_offset) = discr_attr.value() {
                    let discr_entry = unit
                        .entry(discr_offset)
                        .map_err(|e| Error::Other(format!("discr DIE: {}", e)))?;
                    let discr_name = discr_entry
                        .attr(DwAt(0x03))
                        .ok()
                        .flatten()
                        .and_then(|a| self.attr_string(&a, unit).ok())
                        .unwrap_or_else(|| "<discriminant>".into());
                    let discr_type =
                        self.resolve_type_ref(&discr_entry, unit, encoding, depth + 1)?;
                    let discr_offset_val = discr_entry
                        .attr(DwAt(0x38)) // DW_AT_data_member_location
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value())
                        .unwrap_or(0);
                    discriminant = Some(Box::new(MemberInfo {
                        name: discr_name,
                        type_info: discr_type,
                        offset: discr_offset_val,
                    }));
                }
            }

            // Walk DW_TAG_variant children
            let mut variant_children = child.children();
            while let Some(variant_child) = variant_children
                .next()
                .map_err(|e| Error::Other(format!("variant child: {}", e)))?
            {
                let variant_entry = variant_child.entry();
                if variant_entry.tag() != DwTag(0x2f) {
                    // Not DW_TAG_variant
                    continue;
                }

                let discr_value = variant_entry
                    .attr(DwAt(0x66)) // DW_AT_discr_value
                    .ok()
                    .flatten()
                    .and_then(|a| a.udata_value());

                // Each variant should have a DW_TAG_member child with the variant struct
                let mut variant_members = Vec::new();
                let mut variant_name = String::new();
                let mut inner = variant_child.children();

                while let Some(member_child) = inner
                    .next()
                    .map_err(|e| Error::Other(format!("member child: {}", e)))?
                {
                    let member_entry = member_child.entry();
                    if member_entry.tag() == DwTag(0x0d) {
                        // DW_TAG_member
                        let mname = member_entry
                            .attr(DwAt(0x03))
                            .ok()
                            .flatten()
                            .and_then(|a| self.attr_string(&a, unit).ok())
                            .unwrap_or_default();
                        if variant_name.is_empty() {
                            variant_name = mname.clone();
                        }
                        let mtype =
                            self.resolve_type_ref(member_entry, unit, encoding, depth + 1)?;
                        let moffset = member_entry
                            .attr(DwAt(0x38))
                            .ok()
                            .flatten()
                            .and_then(|a| a.udata_value())
                            .unwrap_or(0);
                        variant_members.push(MemberInfo {
                            name: mname,
                            type_info: mtype,
                            offset: moffset,
                        });
                    }
                }

                if variant_name.is_empty() {
                    variant_name = format!("variant_{}", variants.len());
                }

                variants.push(EnumVariant {
                    discr_value,
                    name: variant_name,
                    members: variant_members,
                });
            }
        }

        Ok((discriminant, variants))
    }

    /// Extract a string value from a DWARF attribute.
    fn attr_string(
        &self,
        attr: &gimli::Attribute<GimliReader>,
        _unit: &Unit<GimliReader>,
    ) -> Result<String> {
        match attr.value() {
            AttributeValue::DebugStrRef(offset) => {
                let s = self
                    .dwarf
                    .debug_str
                    .get_str(offset)
                    .map_err(|e| Error::Other(format!("debug_str: {}", e)))?;
                let cow = s.to_string_lossy().map_err(|e| Error::Other(format!("str: {}", e)))?;
                Ok(cow.to_string())
            }
            AttributeValue::String(s) => {
                let cow = s.to_string_lossy().map_err(|e| Error::Other(format!("str: {}", e)))?;
                Ok(cow.to_string())
            }
            _ => Ok(String::new()),
        }
    }

    /// Get the encoding for expression evaluation.
    pub fn encoding_for_pc(&self, pc: u64) -> Result<Encoding> {
        let mut units = self.dwarf.units();
        while let Some(header) =
            units.next().map_err(|e| Error::Other(format!("units: {}", e)))?
        {
            let unit = self
                .dwarf
                .unit(header)
                .map_err(|e| Error::Other(format!("unit: {}", e)))?;
            if self.unit_contains_pc(&unit, pc)? {
                return Ok(unit.encoding());
            }
        }
        // Default x86_64 encoding
        Ok(Encoding {
            address_size: 8,
            format: gimli::Format::Dwarf64,
            version: 4,
        })
    }
}

/// Format a variable's value based on its type.
pub fn format_value(data: &[u8], type_info: &TypeInfo) -> String {
    let size = type_info.byte_size as usize;
    if data.len() < size {
        return "<incomplete>".into();
    }
    let bytes = &data[..size.min(data.len())];

    match &type_info.kind {
        TypeKind::SignedInt => match size {
            1 => format!("{}", bytes[0] as i8),
            2 => format!("{}", i16::from_le_bytes(bytes[..2].try_into().unwrap())),
            4 => format!("{}", i32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => format!("{}", i64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => format_hex(bytes),
        },
        TypeKind::UnsignedInt => match size {
            1 => format!("{}", bytes[0]),
            2 => format!("{}", u16::from_le_bytes(bytes[..2].try_into().unwrap())),
            4 => format!("{}", u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => format!("{}", u64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => format_hex(bytes),
        },
        TypeKind::Float => match size {
            4 => format!(
                "{}",
                f32::from_le_bytes(bytes[..4].try_into().unwrap())
            ),
            8 => format!(
                "{}",
                f64::from_le_bytes(bytes[..8].try_into().unwrap())
            ),
            _ => format_hex(bytes),
        },
        TypeKind::Bool => {
            if bytes[0] == 0 {
                "false".into()
            } else {
                "true".into()
            }
        }
        TypeKind::Char => {
            let ch = bytes[0];
            if ch.is_ascii_graphic() || ch == b' ' {
                format!("'{}'", ch as char)
            } else {
                format!("'\\x{:02x}'", ch)
            }
        }
        TypeKind::Pointer(_) => {
            let addr = match size {
                4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                _ => 0,
            };
            format!("0x{:x}", addr)
        }
        TypeKind::Array { element, count } => {
            let elem_size = element.byte_size as usize;
            if elem_size == 0 {
                return "<zero-size array>".into();
            }
            let n = count.unwrap_or_else(|| (data.len() / elem_size) as u64) as usize;
            let max_show = n.min(8);
            let mut parts = Vec::new();
            for i in 0..max_show {
                let start = i * elem_size;
                let end = start + elem_size;
                if end <= data.len() {
                    parts.push(format_value(&data[start..end], element));
                }
            }
            if n > max_show {
                parts.push("...".into());
            }
            format!("[{}]", parts.join(", "))
        }
        TypeKind::Struct(members) => {
            let mut parts = Vec::new();
            for m in members.iter().take(8) {
                let start = m.offset as usize;
                let end = start + m.type_info.byte_size as usize;
                let val = if end <= data.len() {
                    format_value(&data[start..end], &m.type_info)
                } else {
                    "<?>".into()
                };
                parts.push(format!("{}: {}", m.name, val));
            }
            if members.len() > 8 {
                parts.push("...".into());
            }
            format!("{{{}}}", parts.join(", "))
        }
        TypeKind::Union(members) => {
            // Display the first member's interpretation
            if let Some(m) = members.first() {
                let start = m.offset as usize;
                let end = start + m.type_info.byte_size as usize;
                let val = if end <= data.len() {
                    format_value(&data[start..end], &m.type_info)
                } else {
                    "<?>".into()
                };
                format!("union {{ {}: {} }}", m.name, val)
            } else {
                format!("union {{}}")
            }
        }
        TypeKind::Enum {
            discriminant,
            variants,
        } => {
            // Read discriminant value to select the active variant
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

            // Find matching variant (or default variant with discr_value == None)
            let active = discr_val
                .and_then(|dv| variants.iter().find(|v| v.discr_value == Some(dv)))
                .or_else(|| variants.iter().find(|v| v.discr_value.is_none()));

            match active {
                Some(v) => {
                    if v.members.is_empty() {
                        v.name.clone()
                    } else {
                        let inner = &v.members;
                        // For single-member variant struct, format its inner fields
                        if inner.len() == 1 {
                            let m = &inner[0];
                            if let TypeKind::Struct(fields) = &m.type_info.kind {
                                if fields.is_empty() {
                                    return v.name.clone();
                                }
                                let mut parts = Vec::new();
                                for f in fields.iter().take(8) {
                                    let start = m.offset as usize + f.offset as usize;
                                    let end = start + f.type_info.byte_size as usize;
                                    let val = if end <= data.len() {
                                        format_value(&data[start..end], &f.type_info)
                                    } else {
                                        "<?>".into()
                                    };
                                    parts.push(val);
                                }
                                return format!("{}({})", v.name, parts.join(", "));
                            }
                        }
                        // Multi-member or non-struct variant
                        let mut parts = Vec::new();
                        for m in inner.iter().take(8) {
                            let start = m.offset as usize;
                            let end = start + m.type_info.byte_size as usize;
                            let val = if end <= data.len() {
                                format_value(&data[start..end], &m.type_info)
                            } else {
                                "<?>".into()
                            };
                            parts.push(val);
                        }
                        format!("{}({})", v.name, parts.join(", "))
                    }
                }
                None => match discr_val {
                    Some(dv) => format!("<unknown variant {}>", dv),
                    None => "<unknown variant>".into(),
                },
            }
        }
        TypeKind::Unknown => format_hex(bytes),
    }
}

fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_signed_int() {
        let ti = TypeInfo {
            name: "int".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };
        assert_eq!(format_value(&(-42i32).to_le_bytes(), &ti), "-42");
        assert_eq!(format_value(&(100i32).to_le_bytes(), &ti), "100");
    }

    #[test]
    fn format_unsigned_int() {
        let ti = TypeInfo {
            name: "unsigned int".into(),
            byte_size: 4,
            kind: TypeKind::UnsignedInt,
        };
        assert_eq!(format_value(&42u32.to_le_bytes(), &ti), "42");
    }

    #[test]
    fn format_float() {
        let ti = TypeInfo {
            name: "float".into(),
            byte_size: 4,
            kind: TypeKind::Float,
        };
        let val = format_value(&3.14f32.to_le_bytes(), &ti);
        assert!(val.starts_with("3.14"));
    }

    #[test]
    fn format_bool_values() {
        let ti = TypeInfo {
            name: "bool".into(),
            byte_size: 1,
            kind: TypeKind::Bool,
        };
        assert_eq!(format_value(&[0], &ti), "false");
        assert_eq!(format_value(&[1], &ti), "true");
    }

    #[test]
    fn format_char_values() {
        let ti = TypeInfo {
            name: "char".into(),
            byte_size: 1,
            kind: TypeKind::Char,
        };
        assert_eq!(format_value(&[b'A'], &ti), "'A'");
        assert_eq!(format_value(&[0x01], &ti), "'\\x01'");
    }

    #[test]
    fn format_pointer() {
        let ti = TypeInfo {
            name: "int*".into(),
            byte_size: 8,
            kind: TypeKind::Pointer(Box::new(TypeInfo {
                name: "int".into(),
                byte_size: 4,
                kind: TypeKind::SignedInt,
            })),
        };
        assert_eq!(
            format_value(&0x7fff0100u64.to_le_bytes(), &ti),
            "0x7fff0100"
        );
    }

    #[test]
    fn format_struct() {
        let ti = TypeInfo {
            name: "point".into(),
            byte_size: 8,
            kind: TypeKind::Struct(vec![
                MemberInfo {
                    name: "x".into(),
                    type_info: TypeInfo {
                        name: "int".into(),
                        byte_size: 4,
                        kind: TypeKind::SignedInt,
                    },
                    offset: 0,
                },
                MemberInfo {
                    name: "y".into(),
                    type_info: TypeInfo {
                        name: "int".into(),
                        byte_size: 4,
                        kind: TypeKind::SignedInt,
                    },
                    offset: 4,
                },
            ]),
        };
        let mut data = Vec::new();
        data.extend_from_slice(&10i32.to_le_bytes());
        data.extend_from_slice(&20i32.to_le_bytes());
        assert_eq!(format_value(&data, &ti), "{x: 10, y: 20}");
    }

    #[test]
    fn format_union() {
        let ti = TypeInfo {
            name: "my_union".into(),
            byte_size: 4,
            kind: TypeKind::Union(vec![
                MemberInfo {
                    name: "as_int".into(),
                    type_info: TypeInfo {
                        name: "int".into(),
                        byte_size: 4,
                        kind: TypeKind::SignedInt,
                    },
                    offset: 0,
                },
                MemberInfo {
                    name: "as_float".into(),
                    type_info: TypeInfo {
                        name: "float".into(),
                        byte_size: 4,
                        kind: TypeKind::Float,
                    },
                    offset: 0,
                },
            ]),
        };
        assert_eq!(
            format_value(&42i32.to_le_bytes(), &ti),
            "union { as_int: 42 }"
        );
    }

    #[test]
    fn format_enum_some() {
        // Simulate Option<i32> = Some(42)
        // Layout: [discriminant:1][padding:3][value:4] = 8 bytes
        let i32_type = TypeInfo {
            name: "i32".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        let ti = TypeInfo {
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
                                    type_info: i32_type,
                                    offset: 0,
                                }]),
                            },
                            offset: 4,
                        }],
                    },
                ],
            },
        };

        // Some(42): discriminant=1, padding, value=42
        let mut data = vec![0u8; 8];
        data[0] = 1; // discriminant = Some
        data[4..8].copy_from_slice(&42i32.to_le_bytes());
        assert_eq!(format_value(&data, &ti), "Some(42)");
    }

    #[test]
    fn format_enum_none() {
        let ti = TypeInfo {
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
                        members: vec![],
                    },
                ],
            },
        };

        // None: discriminant=0
        let mut data = vec![0u8; 8];
        data[0] = 0;
        assert_eq!(format_value(&data, &ti), "None");
    }
}
