//! FFI fixture: extern blocks, foreign calls and inline assembly.

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
}

/// Wraps the foreign `socket` call.
pub fn create_socket() -> i32 {
    // SAFETY: all arguments are valid constants.
    unsafe { socket(2, 1, 0) }
}

/// Never called from the fixture entry points.
pub fn never_called() -> i32 {
    unsafe { socket(2, 1, 0) }
}

/// A no-op inline assembly snippet (x86_64 only).
#[cfg(target_arch = "x86_64")]
pub fn nop() {
    // SAFETY: a nop has no side effects.
    unsafe { core::arch::asm!("nop") };
}
