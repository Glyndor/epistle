//! Network helpers shared by the listener accept loops.
//!
//! The dual-stack `::` listener (`crate::cli::serve_bind`) accepts
//! both IPv4 and IPv6 connections. Linux reports the peer of an
//! IPv4 connection over that listener as the v4-mapped IPv6 form
//! `::ffff:a.b.c.d`, which then propagates everywhere an `IPv4`-
//! typed value is expected: SPF (`ip4:` mechanisms never match),
//! DNSBL (queries the IPv6 reverse zone instead of the IPv4 one),
//! the ban table, per-IP rate limits, greylisting keys, API-key
//! CIDR allowlists and the audit log.
//!
//! Every `listener.accept()` and every `ConnectInfo<SocketAddr>`
//! extracted by the axum listeners routes the peer through
//! [`canonical_peer`] so the rest of the server sees a single IPv4
//! `IpAddr::V4` for an IPv4 client, never the v4-mapped v6 form.
//! The helper is a one-line wrapper around `IpAddr::to_canonical`
//! (stable since Rust 1.82; the crate's `rust-version` is 1.94) so a
//! future Rust upgrade cannot silently regress this invariant.

pub mod accept;
pub mod body_deadline;
pub mod conn_limit;
pub mod deadline;
pub mod http_serve;
mod https_url;
pub mod per_account_conn;
pub mod response_writer;
#[cfg(test)]
pub(crate) mod tests;
pub mod trusted_ip;

pub use https_url::{HttpsUrl, HttpsUrlError};

use std::net::SocketAddr;

/// Return the peer address with an IPv4 client represented as a
/// plain `IpAddr::V4` regardless of which listener accepted the
/// connection. The port is preserved verbatim.
///
/// IPv6 addresses and already-canonical IPv4 addresses are returned
/// unchanged. The v4-mapped IPv6 form (`::ffff:a.b.c.d`) becomes the
/// equivalent IPv4 address; the helper never allocates.
pub fn canonical_peer(addr: SocketAddr) -> SocketAddr {
	SocketAddr::new(addr.ip().to_canonical(), addr.port())
}
