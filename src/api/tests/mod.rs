//! The API tests, one folder per topic: the routes every deployment
//! answers, the API keys and their scopes, the account surfaces, the
//! JMAP WebSocket, the limits a submission meets and the isolation
//! between tenants.

pub use super::*;

pub(in crate::api) mod hostile_wire;

pub(super) mod base;

pub(super) mod access;
pub(super) mod accounts;
pub(super) mod authentication;
pub(super) mod changes;
pub(super) mod jmap_email;
pub(super) mod jmap_state;
pub(super) mod jmap_ws;
pub(super) mod keys;
pub(super) mod routes;
pub(super) mod send;
pub(super) mod sieve;
pub(super) mod submissions;
pub(super) mod switches;
pub(super) mod tenancy;
