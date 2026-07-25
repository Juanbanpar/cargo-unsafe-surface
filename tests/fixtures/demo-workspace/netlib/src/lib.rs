//! Library fixture: safe wrappers around unsafe code, manual Send/Sync,
//! unions, mutable statics, MaybeUninit and feature-gated code.

pub mod socket;

/// A handle that is safe to send because the pointer is never
/// dereferenced.
pub struct Handle(*mut u8);

// SAFETY: the raw pointer is opaque and never dereferenced.
unsafe impl Send for Handle {}

// SAFETY: no interior mutability exists.
unsafe impl Sync for Handle {}

/// An unsafe trait with an unsafe impl.
pub unsafe trait RawAccess {}

struct RawHandle;

// SAFETY: RawHandle upholds the RawAccess invariants.
unsafe impl RawAccess for RawHandle {}

static mut CONNECTIONS: u64 = 0;

/// Public safe API that hides unsafe operations.
pub fn run() {
    // SAFETY: the header layout is validated before this call.
    unsafe { parse_header() };

    unsafe {
        // SAFETY: only ever written from one thread during startup.
        CONNECTIONS += 1;
    }
}

/// # Safety
/// Callers must uphold the header invariants described above.
unsafe fn parse_header() {}

/// Union field access requires unsafe.
pub union IntOrFloat {
    pub int: u32,
    pub float: f32,
}

/// Reads the union as an integer.
pub fn as_int(value: IntOrFloat) -> u32 {
    // SAFETY: the value was constructed as `int`.
    unsafe { value.int }
}

/// Uses MaybeUninit for an output buffer.
pub fn scratch_byte() -> u8 {
    let mut slot = core::mem::MaybeUninit::<u8>::uninit();
    // SAFETY: the slot is written exactly once before being read.
    unsafe {
        slot.as_mut_ptr().write(7);
        slot.assume_init()
    }
}

/// Unchecked slice access.
pub fn first_unchecked(data: &[u8]) -> u8 {
    // SAFETY: callers pass non-empty slices.
    unsafe { *data.get_unchecked(0) }
}

/// Only compiled with the `tls` feature.
#[cfg(feature = "tls")]
pub fn run_tls() {
    unsafe { parse_header() };
}

/// Never called from the fixture entry points.
pub fn unreachable_helper() {
    unsafe { parse_header() };
}
