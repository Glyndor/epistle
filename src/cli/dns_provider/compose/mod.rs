//! The generated compose file, with the DNS credential the configuration
//! names reachable inside the container that writes the zone: `certs` when
//! the stack runs the certificates container, `mail` otherwise.
//!
//! A host path is not visible inside the container unless the generated
//! compose file mounts it, and the generated compose file is the only place
//! that says what the container sees: `stack update` re-renders it from the
//! file itself (`init::regenerate`), so a credential that never reaches the
//! compose file is a credential the container never has.
//!
//! The file is rewritten in the order this tool writes it, the way
//! `stack resources set` rewrites it, so the change is reported in words:
//! what the container read before and what it reads after.

mod describe;
mod lock;
mod overrides;
mod services;
mod token;
mod types;

pub(super) use lock::lock_compose;
pub(crate) use services::credential_service;
pub(super) use token::with_token;
pub(super) use types::{TokenChange, TokenSource, TokenUpdate};
