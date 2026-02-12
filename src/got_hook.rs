//! GOT/PLT hooking for function interception.
//!
//! Overwrites Global Offset Table entries to redirect function calls
//! in the debugged process. Useful for monitoring or replacing library calls.

use crate::types::VirtAddr;

/// A GOT hook entry tracking the original and replacement targets.
#[derive(Debug, Clone)]
pub struct GotHook {
    /// Name of the hooked function.
    pub function_name: String,
    /// Address of the GOT slot.
    pub got_address: VirtAddr,
    /// Original function pointer that was in the GOT slot.
    pub original_target: u64,
    /// Replacement function pointer written to the GOT slot.
    pub hook_target: u64,
    /// Whether the hook is currently active.
    pub is_active: bool,
}

/// Manages GOT hooks for a debugged process.
pub struct GotHookManager {
    hooks: Vec<GotHook>,
}

impl GotHookManager {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Record a hook installation.
    pub fn record_hook(
        &mut self,
        function_name: String,
        got_address: VirtAddr,
        original_target: u64,
        hook_target: u64,
    ) -> usize {
        let idx = self.hooks.len();
        self.hooks.push(GotHook {
            function_name,
            got_address,
            original_target,
            hook_target,
            is_active: true,
        });
        idx
    }

    /// Get an active hook by function name.
    pub fn get_hook(&self, function_name: &str) -> Option<&GotHook> {
        self.hooks
            .iter()
            .find(|h| h.function_name == function_name && h.is_active)
    }

    /// Mark a hook as inactive (after restoring original GOT value).
    pub fn deactivate_hook(&mut self, function_name: &str) -> Option<&GotHook> {
        if let Some(hook) = self
            .hooks
            .iter_mut()
            .find(|h| h.function_name == function_name && h.is_active)
        {
            hook.is_active = false;
            Some(hook)
        } else {
            None
        }
    }

    /// List all active hooks.
    pub fn active_hooks(&self) -> Vec<&GotHook> {
        self.hooks.iter().filter(|h| h.is_active).collect()
    }

    /// List all hooks (including inactive).
    pub fn all_hooks(&self) -> &[GotHook] {
        &self.hooks
    }
}

/// Build a monitoring trampoline for x86_64.
///
/// The trampoline saves caller-saved registers, triggers INT3 so the
/// debugger gets control, restores registers, and jumps to the original
/// function.
///
/// Layout (39 bytes):
/// ```text
///   push rax; push rcx; push rdx; push rsi; push rdi
///   push r8; push r9; push r10; push r11
///   int3                   ; debugger intercepts here
///   pop r11; pop r10; pop r9; pop r8
///   pop rdi; pop rsi; pop rdx; pop rcx; pop rax
///   movabs rax, <original> ; load original function address
///   jmp rax                ; tail-call original function
/// ```
pub fn build_trampoline(original_target: u64) -> Vec<u8> {
    let mut code = Vec::new();

    // Save caller-saved registers
    code.push(0x50);                         // push rax
    code.push(0x51);                         // push rcx
    code.push(0x52);                         // push rdx
    code.push(0x56);                         // push rsi
    code.push(0x57);                         // push rdi
    code.extend_from_slice(&[0x41, 0x50]);   // push r8
    code.extend_from_slice(&[0x41, 0x51]);   // push r9
    code.extend_from_slice(&[0x41, 0x52]);   // push r10
    code.extend_from_slice(&[0x41, 0x53]);   // push r11

    // INT3 — debugger intercepts here
    code.push(0xCC);

    // Restore registers
    code.extend_from_slice(&[0x41, 0x5B]);   // pop r11
    code.extend_from_slice(&[0x41, 0x5A]);   // pop r10
    code.extend_from_slice(&[0x41, 0x59]);   // pop r9
    code.extend_from_slice(&[0x41, 0x58]);   // pop r8
    code.push(0x5F);                         // pop rdi
    code.push(0x5E);                         // pop rsi
    code.push(0x5A);                         // pop rdx
    code.push(0x59);                         // pop rcx
    code.push(0x58);                         // pop rax

    // movabs rax, <original_target>
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&original_target.to_le_bytes());

    // jmp rax
    code.extend_from_slice(&[0xFF, 0xE0]);

    code
}

/// Expected size of the trampoline in bytes.
pub const TRAMPOLINE_SIZE: usize = 39;

/// Check if a GOT address falls in a writable memory region.
///
/// Returns false if the region is read-only (full RELRO), meaning
/// GOT hooking is not possible without `mprotect`.
pub fn is_got_writable(got_addr: u64, regions: &[(u64, u64, bool)]) -> bool {
    regions
        .iter()
        .any(|&(start, end, writable)| got_addr >= start && got_addr < end && writable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_record_and_get() {
        let mut mgr = GotHookManager::new();
        mgr.record_hook(
            "puts".into(),
            VirtAddr(0x601020),
            0x7ffff7a649c0,
            0x400100,
        );
        assert_eq!(mgr.active_hooks().len(), 1);
        let hook = mgr.get_hook("puts").unwrap();
        assert_eq!(hook.original_target, 0x7ffff7a649c0);
        assert_eq!(hook.hook_target, 0x400100);
    }

    #[test]
    fn manager_deactivate() {
        let mut mgr = GotHookManager::new();
        mgr.record_hook("puts".into(), VirtAddr(0x601020), 0x7fff0000, 0x400100);
        assert_eq!(mgr.active_hooks().len(), 1);
        mgr.deactivate_hook("puts");
        assert_eq!(mgr.active_hooks().len(), 0);
        assert!(mgr.get_hook("puts").is_none());
    }

    #[test]
    fn manager_not_found() {
        let mgr = GotHookManager::new();
        assert!(mgr.get_hook("nonexistent").is_none());
    }

    #[test]
    fn trampoline_size() {
        let code = build_trampoline(0xDEADBEEF12345678);
        assert_eq!(code.len(), TRAMPOLINE_SIZE);
    }

    #[test]
    fn trampoline_contains_int3() {
        let code = build_trampoline(0x1234);
        assert!(code.contains(&0xCC));
    }

    #[test]
    fn trampoline_contains_target() {
        let target = 0xDEADBEEF12345678u64;
        let code = build_trampoline(target);
        let target_bytes = target.to_le_bytes();
        assert!(code.windows(8).any(|w| w == target_bytes));
    }

    #[test]
    fn trampoline_starts_with_push() {
        let code = build_trampoline(0x1234);
        assert_eq!(code[0], 0x50); // push rax
    }

    #[test]
    fn trampoline_ends_with_jmp_rax() {
        let code = build_trampoline(0x1234);
        let len = code.len();
        assert_eq!(code[len - 2], 0xFF);
        assert_eq!(code[len - 1], 0xE0);
    }

    #[test]
    fn got_writable_check() {
        let regions = vec![
            (0x600000u64, 0x602000u64, true),
            (0x400000u64, 0x401000u64, false),
        ];
        assert!(is_got_writable(0x601020, &regions));
        assert!(!is_got_writable(0x400500, &regions));
        assert!(!is_got_writable(0x700000, &regions));
    }

    #[test]
    fn multiple_hooks() {
        let mut mgr = GotHookManager::new();
        mgr.record_hook("puts".into(), VirtAddr(0x601020), 0x7fff0000, 0x400100);
        mgr.record_hook("malloc".into(), VirtAddr(0x601028), 0x7fff1000, 0x400200);
        assert_eq!(mgr.active_hooks().len(), 2);
        assert_eq!(mgr.all_hooks().len(), 2);
    }
}
