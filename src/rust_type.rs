//! Rust symbol demangling, type detection, and pretty-printing.
//!
//! Provides three main capabilities for Rust-specialized debugging:
//!
//! 1. **Symbol demangling** — Converts mangled Rust (`_ZN`, `_R`) and C++
//!    symbols to human-readable names via [`demangle_symbol`].
//! 2. **Type detection** — Identifies Rust standard library types (Vec, String,
//!    Option, etc.) from DWARF type names via [`detect_rust_type`].
//! 3. **Pretty-printing** — Formats Rust types according to their memory layout
//!    (e.g. `Vec<i32>` as `[1, 2, 3]`) via [`format_rust_value`].

use crate::variables::{TypeInfo, TypeKind};

/// Demangle a Rust or C++ symbol name.
///
/// Tries Rust demangling first (both legacy `_ZN` and v0 `_R` schemes),
/// then falls back to C++ demangling. Returns the original name if neither
/// applies. Hash suffixes are stripped using the `{:#}` format.
pub fn demangle_symbol(mangled: &str) -> String {
    // Try Rust demangling (handles both legacy _ZN and v0 _R prefixes)
    if let Ok(demangled) = rustc_demangle::try_demangle(mangled) {
        // {:#} strips the hash suffix (e.g. "::h1a2b3c4d5e6f7g8")
        return format!("{:#}", demangled);
    }

    // Try C++ demangling
    if let Ok(sym) = cpp_demangle::Symbol::new(mangled.as_bytes()) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return demangled;
        }
    }

    // Return original name unchanged
    mangled.to_string()
}

/// Known Rust standard library types that get special pretty-printing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustType {
    /// `alloc::vec::Vec<T>`
    Vec,
    /// `alloc::string::String`
    String,
    /// `&str` / `&mut str`
    Str,
    /// `&[T]` / `&mut [T]`
    Slice,
    /// `core::option::Option<T>`
    Option,
    /// `core::result::Result<T, E>`
    Result,
    /// `alloc::boxed::Box<T>`
    Box,
    /// `alloc::rc::Rc<T>`
    Rc,
    /// `alloc::sync::Arc<T>`
    Arc,
}

/// Detect a Rust standard library type from a DWARF type name.
///
/// Rustc emits human-readable type names in DWARF info, so we can
/// pattern-match against them.
pub fn detect_rust_type(type_name: &str) -> Option<RustType> {
    let name = type_name.trim();

    // &str / &mut str
    if name == "&str" || name == "&mut str" {
        return Some(RustType::Str);
    }

    // &[T] / &mut [T] — slice references
    if (name.starts_with("&[") || name.starts_with("&mut [")) && name.ends_with(']') {
        return Some(RustType::Slice);
    }

    // String
    if name == "alloc::string::String" || name == "String" {
        return Some(RustType::String);
    }

    // Vec<T>
    if name.starts_with("alloc::vec::Vec<") || name.starts_with("Vec<") {
        return Some(RustType::Vec);
    }

    // Option<T>
    if name.starts_with("core::option::Option<") || name.starts_with("Option<") {
        return Some(RustType::Option);
    }

    // Result<T, E>
    if name.starts_with("core::result::Result<") || name.starts_with("Result<") {
        return Some(RustType::Result);
    }

    // Box<T>
    if name.starts_with("alloc::boxed::Box<") || name.starts_with("Box<") {
        return Some(RustType::Box);
    }

    // Rc<T>
    if name.starts_with("alloc::rc::Rc<") || name.starts_with("Rc<") {
        return Some(RustType::Rc);
    }

    // Arc<T>
    if name.starts_with("alloc::sync::Arc<") || name.starts_with("Arc<") {
        return Some(RustType::Arc);
    }

    None
}

/// Maximum number of elements to display for Vec/slice.
const MAX_ELEMENTS: usize = 32;

/// Maximum string length to display.
const MAX_STRING_LEN: usize = 256;

/// Read a u64 from a byte slice in little-endian.
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Try to format a Rust standard library type with pretty-printing.
///
/// Returns `Some(formatted_string)` if the type was recognized as a Rust type
/// and successfully formatted, or `None` to fall back to the generic formatter.
///
/// The `read_mem` closure reads `len` bytes from address `addr` in the target
/// process, enabling this function to dereference pointers. This function
/// is platform-independent — all OS interaction goes through the closure.
pub fn format_rust_value(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    let rust_type = detect_rust_type(&type_info.name)?;

    match rust_type {
        RustType::Str => format_str_ref(data, read_mem),
        RustType::String => format_string(data, read_mem),
        RustType::Vec => format_vec(data, type_info, read_mem),
        RustType::Slice => format_slice(data, type_info, read_mem),
        RustType::Option => None, // Handled by Enum variant in format_value
        RustType::Result => None, // Handled by Enum variant in format_value
        RustType::Box => format_box(data, type_info, read_mem),
        RustType::Rc => format_rc(data, type_info, read_mem),
        RustType::Arc => format_arc(data, type_info, read_mem),
    }
}

/// Format `&str`: `[ptr:8][len:8]` → `"hello"`
fn format_str_ref(
    data: &[u8],
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    if data.len() < 16 {
        return None;
    }
    let ptr = read_u64(data, 0)?;
    let len = read_u64(data, 8)? as usize;
    if ptr == 0 {
        return Some("\"<null>\"".into());
    }
    let len = len.min(MAX_STRING_LEN);
    let bytes = read_mem(ptr, len).ok()?;
    let s = String::from_utf8_lossy(&bytes);
    if len < read_u64(data, 8)? as usize {
        Some(format!("\"{}\"...", s))
    } else {
        Some(format!("\"{}\"", s))
    }
}

/// Format `String`: `[ptr:8][cap:8][len:8]` → `"world"`
fn format_string(
    data: &[u8],
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    if data.len() < 24 {
        return None;
    }
    let ptr = read_u64(data, 0)?;
    let _cap = read_u64(data, 8)?;
    let len = read_u64(data, 16)? as usize;
    if ptr == 0 {
        return Some("\"<null>\"".into());
    }
    let len = len.min(MAX_STRING_LEN);
    let bytes = read_mem(ptr, len).ok()?;
    let s = String::from_utf8_lossy(&bytes);
    let original_len = read_u64(data, 16)? as usize;
    if len < original_len {
        Some(format!("\"{}\"...", s))
    } else {
        Some(format!("\"{}\"", s))
    }
}

/// Infer element size from Vec/slice type info.
///
/// Digs through the struct members to find the pointer type, then gets
/// the pointee size. Falls back to 1 byte if unresolvable.
fn infer_element_size(type_info: &TypeInfo) -> usize {
    // Vec<T> is a struct with a RawVec<T> which contains a Unique<T>
    // which contains *const T. We dig through the wrappers.
    if let TypeKind::Struct(members) = &type_info.kind {
        for m in members {
            if let Some(size) = dig_element_size(&m.type_info) {
                return size;
            }
        }
    }
    // For slices (&[T]), it's a fat pointer: [*const T, usize]
    if let TypeKind::Pointer(pointee) = &type_info.kind {
        if pointee.byte_size > 0 {
            return pointee.byte_size as usize;
        }
    }
    1 // fallback: treat as bytes
}

/// Recursively dig through wrapper types (Box→Unique→NonNull→*const T)
/// to find the inner element size.
fn dig_element_size(type_info: &TypeInfo) -> Option<usize> {
    match &type_info.kind {
        TypeKind::Pointer(pointee) => {
            if pointee.byte_size > 0 {
                Some(pointee.byte_size as usize)
            } else {
                None
            }
        }
        TypeKind::Struct(members) => {
            for m in members {
                if let Some(size) = dig_element_size(&m.type_info) {
                    return Some(size);
                }
            }
            None
        }
        _ => None,
    }
}

/// Format `Vec<T>`: `[ptr:8][cap:8][len:8]` → `[1, 2, 3]`
fn format_vec(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    if data.len() < 24 {
        return None;
    }
    let ptr = read_u64(data, 0)?;
    let _cap = read_u64(data, 8)?;
    let len = read_u64(data, 16)? as usize;
    if ptr == 0 && len == 0 {
        return Some("[]".into());
    }
    if ptr == 0 {
        return Some("<null Vec>".into());
    }

    let elem_size = infer_element_size(type_info);
    let elem_type = infer_element_type(type_info);
    let show = len.min(MAX_ELEMENTS);
    let bytes = read_mem(ptr, show * elem_size).ok()?;

    let parts = format_elements(&bytes, elem_size, show, elem_type.as_ref());
    if len > show {
        Some(format!("[{}, ... ({} total)]", parts.join(", "), len))
    } else {
        Some(format!("[{}]", parts.join(", ")))
    }
}

/// Format `&[T]`: `[ptr:8][len:8]` → `[1, 2, 3]`
fn format_slice(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    if data.len() < 16 {
        return None;
    }
    let ptr = read_u64(data, 0)?;
    let len = read_u64(data, 8)? as usize;
    if ptr == 0 && len == 0 {
        return Some("[]".into());
    }
    if ptr == 0 {
        return Some("<null slice>".into());
    }

    let elem_size = infer_element_size(type_info);
    let elem_type = infer_element_type(type_info);
    let show = len.min(MAX_ELEMENTS);
    let bytes = read_mem(ptr, show * elem_size).ok()?;

    let parts = format_elements(&bytes, elem_size, show, elem_type.as_ref());
    if len > show {
        Some(format!("[{}, ... ({} total)]", parts.join(", "), len))
    } else {
        Some(format!("[{}]", parts.join(", ")))
    }
}

/// Infer the element TypeInfo from Vec/slice type wrappers.
fn infer_element_type(type_info: &TypeInfo) -> Option<TypeInfo> {
    if let TypeKind::Struct(members) = &type_info.kind {
        for m in members {
            if let Some(ti) = dig_element_type(&m.type_info) {
                return Some(ti);
            }
        }
    }
    if let TypeKind::Pointer(pointee) = &type_info.kind {
        return Some(pointee.as_ref().clone());
    }
    None
}

/// Dig through wrapper types to find the inner pointee TypeInfo.
fn dig_element_type(type_info: &TypeInfo) -> Option<TypeInfo> {
    match &type_info.kind {
        TypeKind::Pointer(pointee) => Some(pointee.as_ref().clone()),
        TypeKind::Struct(members) => {
            for m in members {
                if let Some(ti) = dig_element_type(&m.type_info) {
                    return Some(ti);
                }
            }
            None
        }
        _ => None,
    }
}

/// Format a sequence of elements from raw bytes.
fn format_elements(
    bytes: &[u8],
    elem_size: usize,
    count: usize,
    elem_type: Option<&TypeInfo>,
) -> Vec<String> {
    let mut parts = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * elem_size;
        let end = start + elem_size;
        if end > bytes.len() {
            break;
        }
        let chunk = &bytes[start..end];
        let s = match elem_type {
            Some(ti) => crate::variables::format_value(chunk, ti),
            None => format_raw_element(chunk),
        };
        parts.push(s);
    }
    parts
}

/// Format a raw element as a hex or integer value.
fn format_raw_element(bytes: &[u8]) -> String {
    match bytes.len() {
        1 => format!("{}", bytes[0]),
        2 => format!("{}", u16::from_le_bytes(bytes.try_into().unwrap())),
        4 => format!("{}", u32::from_le_bytes(bytes.try_into().unwrap())),
        8 => format!("{}", u64::from_le_bytes(bytes.try_into().unwrap())),
        _ => bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Format `Box<T>`: dereference the pointer and format the inner value.
fn format_box(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    let ptr = read_u64(data, 0)?;
    if ptr == 0 {
        return Some("Box(<null>)".into());
    }

    let inner_type = dig_through_wrappers(type_info)?;
    if inner_type.byte_size == 0 {
        return Some(format!("Box(0x{:x})", ptr));
    }
    let inner_data = read_mem(ptr, inner_type.byte_size as usize).ok()?;
    let inner_str = crate::variables::format_value(&inner_data, &inner_type);
    Some(format!("Box({})", inner_str))
}

/// Format `Rc<T>`: `[ptr]` → at ptr: `[strong:8][weak:8][value:T]`
fn format_rc(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    format_refcounted(data, type_info, read_mem, "Rc")
}

/// Format `Arc<T>`: same layout as Rc (with atomic counters).
fn format_arc(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
) -> Option<String> {
    format_refcounted(data, type_info, read_mem, "Arc")
}

/// Common formatter for Rc/Arc.
/// Layout at ptr: `[strong:usize][weak:usize][value:T]`
fn format_refcounted(
    data: &[u8],
    type_info: &TypeInfo,
    read_mem: &dyn Fn(u64, usize) -> crate::error::Result<Vec<u8>>,
    prefix: &str,
) -> Option<String> {
    let ptr = read_u64(data, 0)?;
    if ptr == 0 {
        return Some(format!("{}(<null>)", prefix));
    }

    // Read the RcBox/ArcInner header: [strong:8][weak:8]
    let header = read_mem(ptr, 16).ok()?;
    let strong = read_u64(&header, 0)?;
    let weak = read_u64(&header, 8)?;

    let inner_type = dig_through_wrappers(type_info);
    let value_str = match inner_type {
        Some(ref ti) if ti.byte_size > 0 => {
            let val_data = read_mem(ptr + 16, ti.byte_size as usize).ok()?;
            crate::variables::format_value(&val_data, ti)
        }
        _ => format!("0x{:x}", ptr + 16),
    };

    Some(format!(
        "{}({}, strong={}, weak={})",
        prefix, value_str, strong, weak
    ))
}

/// Dig through Box→Unique→NonNull→*const T wrappers to find the inner type.
fn dig_through_wrappers(type_info: &TypeInfo) -> Option<TypeInfo> {
    match &type_info.kind {
        TypeKind::Pointer(pointee) => Some(pointee.as_ref().clone()),
        TypeKind::Struct(members) => {
            // Box, Unique, NonNull, Rc, Arc all wrap inner types in struct layers.
            // Look through members for pointer or nested struct.
            for m in members {
                if let Some(ti) = dig_through_wrappers(&m.type_info) {
                    return Some(ti);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, Result};
    use crate::variables::{MemberInfo, TypeInfo, TypeKind};

    // ── demangle_symbol tests ────────────────────────────────────────

    #[test]
    fn demangle_rust_legacy() {
        // Legacy Rust mangling: _ZN prefix
        let result = demangle_symbol("_ZN5hello4main17h05af5e12a3b6de18E");
        assert_eq!(result, "hello::main");
    }

    #[test]
    fn demangle_rust_v0() {
        // v0 Rust mangling: _R prefix
        let result = demangle_symbol("_RNvCs1234_5hello4main");
        // Should at least contain "hello" and "main"
        assert!(result.contains("hello"));
        assert!(result.contains("main"));
    }

    #[test]
    fn demangle_cpp() {
        let result = demangle_symbol("_ZN3foo3barEv");
        assert_eq!(result, "foo::bar()");
    }

    #[test]
    fn demangle_plain_name() {
        assert_eq!(demangle_symbol("main"), "main");
        assert_eq!(demangle_symbol("printf"), "printf");
    }

    #[test]
    fn demangle_strips_hash() {
        // The {:#} format should strip the hash suffix
        let result = demangle_symbol("_ZN3std2io5stdio6_print17h3c43e94d1e8a4b5eE");
        assert!(!result.contains("::h"), "hash should be stripped: {}", result);
    }

    // ── detect_rust_type tests ───────────────────────────────────────

    #[test]
    fn detect_vec() {
        assert_eq!(detect_rust_type("Vec<i32>"), Some(RustType::Vec));
        assert_eq!(
            detect_rust_type("alloc::vec::Vec<u8>"),
            Some(RustType::Vec)
        );
    }

    #[test]
    fn detect_string() {
        assert_eq!(detect_rust_type("String"), Some(RustType::String));
        assert_eq!(
            detect_rust_type("alloc::string::String"),
            Some(RustType::String)
        );
    }

    #[test]
    fn detect_str_ref() {
        assert_eq!(detect_rust_type("&str"), Some(RustType::Str));
        assert_eq!(detect_rust_type("&mut str"), Some(RustType::Str));
    }

    #[test]
    fn detect_slice() {
        assert_eq!(detect_rust_type("&[u8]"), Some(RustType::Slice));
        assert_eq!(detect_rust_type("&mut [i32]"), Some(RustType::Slice));
    }

    #[test]
    fn detect_option() {
        assert_eq!(detect_rust_type("Option<i32>"), Some(RustType::Option));
        assert_eq!(
            detect_rust_type("core::option::Option<String>"),
            Some(RustType::Option)
        );
    }

    #[test]
    fn detect_result() {
        assert_eq!(
            detect_rust_type("Result<i32, String>"),
            Some(RustType::Result)
        );
        assert_eq!(
            detect_rust_type("core::result::Result<(), Error>"),
            Some(RustType::Result)
        );
    }

    #[test]
    fn detect_box() {
        assert_eq!(detect_rust_type("Box<dyn Error>"), Some(RustType::Box));
        assert_eq!(
            detect_rust_type("alloc::boxed::Box<i32>"),
            Some(RustType::Box)
        );
    }

    #[test]
    fn detect_rc() {
        assert_eq!(detect_rust_type("Rc<String>"), Some(RustType::Rc));
        assert_eq!(
            detect_rust_type("alloc::rc::Rc<Vec<u8>>"),
            Some(RustType::Rc)
        );
    }

    #[test]
    fn detect_arc() {
        assert_eq!(detect_rust_type("Arc<Mutex<i32>>"), Some(RustType::Arc));
        assert_eq!(
            detect_rust_type("alloc::sync::Arc<String>"),
            Some(RustType::Arc)
        );
    }

    #[test]
    fn detect_non_rust_type() {
        assert_eq!(detect_rust_type("int"), None);
        assert_eq!(detect_rust_type("std::vector<int>"), None);
        assert_eq!(detect_rust_type("MyCustomType"), None);
    }

    // ── format_rust_value tests ──────────────────────────────────────

    /// Helper to create a mock memory reader from a map of address→data.
    fn mock_reader(
        memory: Vec<(u64, Vec<u8>)>,
    ) -> impl Fn(u64, usize) -> Result<Vec<u8>> {
        move |addr: u64, len: usize| {
            for (base, data) in &memory {
                let end = base + data.len() as u64;
                if addr >= *base && addr + len as u64 <= end {
                    let offset = (addr - base) as usize;
                    return Ok(data[offset..offset + len].to_vec());
                }
            }
            Err(Error::Other(format!("no mock memory at 0x{:x}", addr)))
        }
    }

    #[test]
    fn format_str_ref_value() {
        let text = b"hello";
        let reader = mock_reader(vec![(0x1000, text.to_vec())]);

        // &str: [ptr:8][len:8]
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // ptr
        data.extend_from_slice(&5u64.to_le_bytes()); // len

        let ti = TypeInfo {
            name: "&str".into(),
            byte_size: 16,
            kind: TypeKind::Struct(vec![]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("\"hello\"".into()));
    }

    #[test]
    fn format_string_value() {
        let text = b"world";
        let reader = mock_reader(vec![(0x2000, text.to_vec())]);

        // String: [ptr:8][cap:8][len:8]
        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u64.to_le_bytes()); // ptr
        data.extend_from_slice(&16u64.to_le_bytes()); // cap
        data.extend_from_slice(&5u64.to_le_bytes()); // len

        let ti = TypeInfo {
            name: "alloc::string::String".into(),
            byte_size: 24,
            kind: TypeKind::Struct(vec![]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("\"world\"".into()));
    }

    #[test]
    fn format_vec_i32() {
        // Vec data: [1i32, 2, 3]
        let mut vec_data = Vec::new();
        vec_data.extend_from_slice(&1i32.to_le_bytes());
        vec_data.extend_from_slice(&2i32.to_le_bytes());
        vec_data.extend_from_slice(&3i32.to_le_bytes());
        let reader = mock_reader(vec![(0x3000, vec_data)]);

        // Vec<i32>: [ptr:8][cap:8][len:8]
        let mut data = Vec::new();
        data.extend_from_slice(&0x3000u64.to_le_bytes()); // ptr
        data.extend_from_slice(&8u64.to_le_bytes()); // cap
        data.extend_from_slice(&3u64.to_le_bytes()); // len

        let i32_type = TypeInfo {
            name: "i32".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        let ti = TypeInfo {
            name: "Vec<i32>".into(),
            byte_size: 24,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "buf".into(),
                type_info: TypeInfo {
                    name: "RawVec<i32>".into(),
                    byte_size: 16,
                    kind: TypeKind::Struct(vec![MemberInfo {
                        name: "ptr".into(),
                        type_info: TypeInfo {
                            name: "Unique<i32>".into(),
                            byte_size: 8,
                            kind: TypeKind::Pointer(Box::new(i32_type)),
                        },
                        offset: 0,
                    }]),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("[1, 2, 3]".into()));
    }

    #[test]
    fn format_empty_vec() {
        let reader = mock_reader(vec![]);

        let mut data = Vec::new();
        data.extend_from_slice(&0u64.to_le_bytes()); // null ptr
        data.extend_from_slice(&0u64.to_le_bytes()); // cap
        data.extend_from_slice(&0u64.to_le_bytes()); // len

        let ti = TypeInfo {
            name: "Vec<u8>".into(),
            byte_size: 24,
            kind: TypeKind::Struct(vec![]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("[]".into()));
    }

    #[test]
    fn format_box_value() {
        let reader = mock_reader(vec![(0x4000, 42i32.to_le_bytes().to_vec())]);

        let mut data = Vec::new();
        data.extend_from_slice(&0x4000u64.to_le_bytes());

        let i32_type = TypeInfo {
            name: "i32".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        let ti = TypeInfo {
            name: "Box<i32>".into(),
            byte_size: 8,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "pointer".into(),
                type_info: TypeInfo {
                    name: "Unique<i32>".into(),
                    byte_size: 8,
                    kind: TypeKind::Pointer(Box::new(i32_type)),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("Box(42)".into()));
    }

    #[test]
    fn format_rc_value() {
        // RcBox layout: [strong:8][weak:8][value:i32(4 bytes)]
        let mut rc_data = Vec::new();
        rc_data.extend_from_slice(&1u64.to_le_bytes()); // strong = 1
        rc_data.extend_from_slice(&1u64.to_le_bytes()); // weak = 1
        rc_data.extend_from_slice(&99i32.to_le_bytes()); // value = 99
        let reader = mock_reader(vec![(0x5000, rc_data)]);

        let mut data = Vec::new();
        data.extend_from_slice(&0x5000u64.to_le_bytes());

        let i32_type = TypeInfo {
            name: "i32".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        let ti = TypeInfo {
            name: "Rc<i32>".into(),
            byte_size: 8,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "ptr".into(),
                type_info: TypeInfo {
                    name: "NonNull<RcBox<i32>>".into(),
                    byte_size: 8,
                    kind: TypeKind::Pointer(Box::new(i32_type)),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("Rc(99, strong=1, weak=1)".into()));
    }

    #[test]
    fn format_arc_value() {
        // ArcInner layout: [strong:8][weak:8][value:i32]
        let mut arc_data = Vec::new();
        arc_data.extend_from_slice(&2u64.to_le_bytes()); // strong = 2
        arc_data.extend_from_slice(&1u64.to_le_bytes()); // weak = 1
        arc_data.extend_from_slice(&77i32.to_le_bytes()); // value = 77
        let reader = mock_reader(vec![(0x6000, arc_data)]);

        let mut data = Vec::new();
        data.extend_from_slice(&0x6000u64.to_le_bytes());

        let i32_type = TypeInfo {
            name: "i32".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        let ti = TypeInfo {
            name: "Arc<i32>".into(),
            byte_size: 8,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "ptr".into(),
                type_info: TypeInfo {
                    name: "NonNull<ArcInner<i32>>".into(),
                    byte_size: 8,
                    kind: TypeKind::Pointer(Box::new(i32_type)),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("Arc(77, strong=2, weak=1)".into()));
    }

    #[test]
    fn format_null_box() {
        let reader = mock_reader(vec![]);
        let data = 0u64.to_le_bytes().to_vec();

        let ti = TypeInfo {
            name: "Box<i32>".into(),
            byte_size: 8,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "pointer".into(),
                type_info: TypeInfo {
                    name: "Unique<i32>".into(),
                    byte_size: 8,
                    kind: TypeKind::Pointer(Box::new(TypeInfo {
                        name: "i32".into(),
                        byte_size: 4,
                        kind: TypeKind::SignedInt,
                    })),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("Box(<null>)".into()));
    }

    #[test]
    fn format_non_rust_type_returns_none() {
        let reader = mock_reader(vec![]);
        let data = 42i32.to_le_bytes().to_vec();

        let ti = TypeInfo {
            name: "int".into(),
            byte_size: 4,
            kind: TypeKind::SignedInt,
        };

        assert_eq!(format_rust_value(&data, &ti, &reader), None);
    }

    #[test]
    fn format_slice_value() {
        // Slice data: [10u8, 20, 30]
        let slice_data = vec![10u8, 20, 30];
        let reader = mock_reader(vec![(0x7000, slice_data)]);

        // &[u8]: [ptr:8][len:8]
        let mut data = Vec::new();
        data.extend_from_slice(&0x7000u64.to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());

        let u8_type = TypeInfo {
            name: "u8".into(),
            byte_size: 1,
            kind: TypeKind::UnsignedInt,
        };

        let ti = TypeInfo {
            name: "&[u8]".into(),
            byte_size: 16,
            kind: TypeKind::Struct(vec![MemberInfo {
                name: "data_ptr".into(),
                type_info: TypeInfo {
                    name: "*const u8".into(),
                    byte_size: 8,
                    kind: TypeKind::Pointer(Box::new(u8_type)),
                },
                offset: 0,
            }]),
        };

        let result = format_rust_value(&data, &ti, &reader);
        assert_eq!(result, Some("[10, 20, 30]".into()));
    }
}
