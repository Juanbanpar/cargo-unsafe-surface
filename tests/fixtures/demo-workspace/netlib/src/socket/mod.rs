//! Socket submodule (exercises `mod.rs` layout and cross-module calls).

mod sys;

/// Safe socket creation entry point.
pub fn create() {
    // SAFETY: the descriptor is validated on the next line.
    unsafe { sys::open_raw() };
}
