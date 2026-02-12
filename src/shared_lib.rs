//! Shared library tracking via the dynamic linker's `r_debug` / `link_map`.
//!
//! Corresponds to sdb's shared library support and book Ch.17.
//!
//! On Linux, the dynamic linker maintains a linked list (`link_map`) of all
//! loaded shared objects.  We locate it via:
//!
//! 1. `/proc/pid/auxv` → `AT_PHDR` (program headers address in memory)
//! 2. Walk program headers → `PT_DYNAMIC` segment
//! 3. Read `.dynamic` section → `DT_DEBUG` entry → `r_debug` pointer
//! 4. `r_debug.r_map` → head of the `link_map` linked list
//!
//! We also expose `r_debug.r_brk` (the rendezvous function) so the caller
//! can set an internal breakpoint to detect library load/unload events.

use crate::error::{Error, Result};
use crate::process::Process;
use crate::procfs;
use crate::types::VirtAddr;

/// A loaded shared library (or the main executable).
#[derive(Debug, Clone)]
pub struct SharedLibrary {
    /// Library pathname (empty string for the main executable / vDSO).
    pub name: String,
    /// Base load address (link_map `l_addr`).
    pub base_addr: u64,
}

/// Information extracted from the dynamic linker's `r_debug` struct.
#[derive(Debug, Clone)]
pub struct RendezvousInfo {
    /// Address of the rendezvous function (`r_brk`).
    ///
    /// Setting a breakpoint here lets the debugger detect shared library
    /// load and unload events.
    pub breakpoint_addr: VirtAddr,
    /// Current loaded libraries.
    pub libraries: Vec<SharedLibrary>,
}

/// Read the list of loaded shared libraries from the tracee's `link_map`.
///
/// This is the main entry point.  It walks:
///   auxv → phdr → PT_DYNAMIC → DT_DEBUG → r_debug → link_map chain.
pub fn read_shared_libraries(process: &Process) -> Result<Vec<SharedLibrary>> {
    let info = read_rendezvous(process)?;
    Ok(info.libraries)
}

/// Read the full rendezvous info (libraries + breakpoint address).
pub fn read_rendezvous(process: &Process) -> Result<RendezvousInfo> {
    let pid = process.pid();

    // Step 1: Read auxiliary vector
    let auxv = procfs::read_auxv(pid)?;
    let phdr_addr = procfs::auxv_lookup(&auxv, procfs::AT_PHDR)
        .ok_or_else(|| Error::Other("AT_PHDR not found in auxv".into()))?;
    let phnum = procfs::auxv_lookup(&auxv, procfs::AT_PHNUM)
        .ok_or_else(|| Error::Other("AT_PHNUM not found in auxv".into()))?;
    let phent = procfs::auxv_lookup(&auxv, procfs::AT_PHENT).unwrap_or(56);

    // Step 2: Read program headers, find PT_DYNAMIC
    let phdrs_size = (phnum * phent) as usize;
    let phdrs_data = process.read_memory(VirtAddr(phdr_addr), phdrs_size)?;

    let mut dynamic_vaddr = None;
    for i in 0..phnum as usize {
        let off = i * phent as usize;
        if off + 56 > phdrs_data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(phdrs_data[off..off + 4].try_into().unwrap());
        if p_type == 2 {
            // PT_DYNAMIC
            let p_vaddr = u64::from_le_bytes(
                phdrs_data[off + 16..off + 24].try_into().unwrap(),
            );
            dynamic_vaddr = Some(p_vaddr);
            break;
        }
    }

    let dynamic_vaddr =
        dynamic_vaddr.ok_or_else(|| Error::Other("PT_DYNAMIC not found".into()))?;

    // Step 3: Read .dynamic section entries, find DT_DEBUG
    // Each entry is 16 bytes: d_tag (i64) + d_val (u64).
    // Read up to 4 KB — plenty for any normal .dynamic.
    let dynamic_data = process.read_memory(VirtAddr(dynamic_vaddr), 4096)?;

    let mut r_debug_addr: u64 = 0;
    for chunk in dynamic_data.chunks(16) {
        if chunk.len() < 16 {
            break;
        }
        let d_tag = i64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let d_val = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        if d_tag == 0 {
            break; // DT_NULL
        }
        if d_tag == 21 {
            // DT_DEBUG
            r_debug_addr = d_val;
            break;
        }
    }

    if r_debug_addr == 0 {
        return Err(Error::Other(
            "DT_DEBUG not found or not yet initialized".into(),
        ));
    }

    // Step 4: Read r_debug struct (x86_64 layout, 40 bytes)
    //   i32  r_version      (offset 0)
    //   [4 bytes padding]
    //   *link_map r_map     (offset 8)
    //   u64  r_brk          (offset 16)
    //   i32  r_state         (offset 24)
    //   [4 bytes padding]
    //   u64  r_ldbase       (offset 32)
    let r_debug_data = process.read_memory(VirtAddr(r_debug_addr), 40)?;
    let r_map = u64::from_le_bytes(r_debug_data[8..16].try_into().unwrap());
    let r_brk = u64::from_le_bytes(r_debug_data[16..24].try_into().unwrap());

    // Step 5: Walk link_map linked list
    let libraries = walk_link_map(process, r_map)?;

    Ok(RendezvousInfo {
        breakpoint_addr: VirtAddr(r_brk),
        libraries,
    })
}

/// Walk the `link_map` linked list starting from `head`.
///
/// Each `link_map` entry on x86_64 is (at least):
///   u64 l_addr       (offset 0)  — base address
///   *char l_name     (offset 8)  — pathname pointer
///   *Dyn  l_ld       (offset 16) — .dynamic pointer
///   *link_map l_next (offset 24) — next entry
///   *link_map l_prev (offset 32) — previous entry
fn walk_link_map(process: &Process, head: u64) -> Result<Vec<SharedLibrary>> {
    let mut libs = Vec::new();
    let mut current = head;

    // Safety limit to prevent infinite loops on corrupted data.
    let mut count = 0;
    const MAX_LIBS: usize = 1024;

    while current != 0 && count < MAX_LIBS {
        let lm_data = process.read_memory(VirtAddr(current), 40)?;
        let l_addr = u64::from_le_bytes(lm_data[0..8].try_into().unwrap());
        let l_name_ptr = u64::from_le_bytes(lm_data[8..16].try_into().unwrap());
        let l_next = u64::from_le_bytes(lm_data[24..32].try_into().unwrap());

        let name = if l_name_ptr != 0 {
            read_cstring(process, l_name_ptr, 512)?
        } else {
            String::new()
        };

        libs.push(SharedLibrary {
            name,
            base_addr: l_addr,
        });

        current = l_next;
        count += 1;
    }

    Ok(libs)
}

/// Read a NUL-terminated string from tracee memory.
fn read_cstring(process: &Process, addr: u64, max_len: usize) -> Result<String> {
    let data = process.read_memory(VirtAddr(addr), max_len)?;
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    Ok(String::from_utf8_lossy(&data[..end]).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_library_display() {
        let lib = SharedLibrary {
            name: "/usr/lib/libc.so.6".into(),
            base_addr: 0x7f000000,
        };
        assert_eq!(lib.name, "/usr/lib/libc.so.6");
        assert_eq!(lib.base_addr, 0x7f000000);
    }

    #[test]
    fn rendezvous_info_fields() {
        let info = RendezvousInfo {
            breakpoint_addr: VirtAddr(0x400100),
            libraries: vec![],
        };
        assert_eq!(info.breakpoint_addr.addr(), 0x400100);
        assert!(info.libraries.is_empty());
    }
}
