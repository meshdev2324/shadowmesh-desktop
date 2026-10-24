//! Headless Slint backend for the desktop client's unit tests.
//!
//! CI runners have no display, and Slint refuses to create any component
//! until a platform backend has been selected: every generated `new()` calls
//! `ensure_backend()` first. Slint's own testing backend simulates a
//! windowing system without one, so the F40 attribution tests can instantiate
//! the real components — and assert that the upstream `AboutSlint` widget was
//! genuinely instantiated — instead of asserting over source text alone.
//!
//! This backend is a dev-dependency and is therefore never linked into the
//! shipped binary.

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialise Slint's headless testing backend, once per process.
///
/// `i_slint_backend_testing::init_no_event_loop()` panics if a platform has
/// already been selected, so the call is guarded by a `Once`.
pub fn init_headless() {
    INIT.call_once(|| {
        i_slint_backend_testing::init_no_event_loop();
    });
}
