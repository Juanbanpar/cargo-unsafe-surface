//! A crate with one malformed module: the analysis must report the
//! syntax error as a diagnostic and keep going.

mod malformed;

/// This function is fine and must still be analysed.
pub fn healthy() {
    unsafe { core::ptr::read(0 as *const u8) };
}
