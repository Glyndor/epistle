//! The dispatchers `epistle account` hands the `forward`, `catch-all` and
//! `2fa` subcommands to. Each prepares the dynamic store, refuses a static
//! account with the config-file hint, and calls its mutator. Split from the
//! parent `mod.rs` to keep it under the per-file code-line cap.

mod catch_all;
mod forward;
mod two_factor;

pub(super) use catch_all::dispatch_catch_all;
pub(super) use forward::dispatch_forward;
pub(super) use two_factor::dispatch_two_factor;
