//! The error answers of the REST API: the `{"error": ...}` body that stays
//! the default, the RFC 9457 problem a client asks for, `WWW-Authenticate`
//! on every `401` and `Retry-After` on every `429`.

pub use super::*;

pub(super) mod base;
mod rate_limited;
mod unauthenticated;
mod validation;
