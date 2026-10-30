//! Bind the listeners `serve` exposes.
//!
//! `TcpListener::bind` on `::` inherits the host's
//! `net.ipv6.bindv6only`: on hosts where the sysctl is `1` (the
//! minority, but allowed) the socket stops accepting IPv4 packets
//! and the mail server loses every connection from an IPv4 client
//! on day one. The fix is to set `IPV6_V6ONLY = false` ourselves on
//! the IPv6-unspecified address before `bind`, so the dual-stack
//! property is a property of the server we ship, not of the host
//! the operator happens to run it on.
//!
//! The IPv6-only fallback kicks in when an operator has both a
//! `[::]:P` and a `0.0.0.0:P` listener configured for the same
//! port. On hosts with `bindv6only=1` the dual-stack `[::]:P` socket
//! would shadow the IPv4 bind; with `bindv6only=0` it would silently
//! route IPv4 traffic away from the explicit `0.0.0.0:P`. Either
//! way, the operator's intent: bind both, one per family. The
//! listener has to win. When the port is already covered by an
//! `0.0.0.0` listener the `[::]` listener is bound with
//! `only_v6(true)` so the two coexist; when it is not, the listener
//! stays dual-stack.
//!
//! Every other address keeps the plain `TcpListener::bind` path:
//! IPv4 loopback and an explicit IPv6 address do not need the
//! socket2 dance.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpListener;

use crate::config::Listener;
#[cfg(test)]
use crate::config::ListenerKind;

/// Bind a listener's socket and log it. Shared by every `serve`
/// listener arm. When the listener's address is the IPv6 unspecified
/// address (`::`), the socket is built with `socket2` so
/// `IPV6_V6ONLY` is off (default) and IPv4 connections reach the
/// same port regardless of the host's `net.ipv6.bindv6only` sysctl.
///
/// `ipv4_any_ports` is the set of port numbers that already have an
/// `0.0.0.0` listener bound by the same `serve` run. When the
/// listener being bound is `[::]:P` and `P` is in that set, the
/// socket is created with `IPV6_V6ONLY = true` so the two coexist
/// instead of one of them failing with `EADDRINUSE`.
pub(super) async fn bind_listener(
	listener: &Listener,
	ipv4_any_ports: &HashSet<u16>,
) -> std::io::Result<TcpListener> {
	let addr = listener.socket_addr();
	let bound = if is_dual_stack_addr(listener.addr) {
		let only_v6 = ipv4_any_ports.contains(&addr.port());
		bind_dual_stack(addr, only_v6)?
	} else {
		TcpListener::bind(addr).await?
	};
	tracing::info!(%addr, kind = ?listener.kind, "listening");
	Ok(bound)
}

/// Bind on the IPv6 unspecified address with `reuse_address(true)`,
/// then convert to a Tokio listener. `only_v6` selects the
/// `IPV6_V6ONLY` socket option:
/// - `false`: the socket accepts both IPv4 and IPv6 traffic
///   regardless of the host's `bindv6only` sysctl. The default
///   when no other listener already covers the port with
///   `0.0.0.0`.
/// - `true`: the socket accepts IPv6 traffic only. Used when an
///   `0.0.0.0:P` listener is already bound, so the two can coexist
///   on the same port instead of one failing with `EADDRINUSE`.
///
/// The backlog is 128, the standard library's default for
/// `TcpListener::bind`, and the socket is non-blocking because
/// Tokio needs that to hand it off. Caller guarantees the address
/// is the IPv6 unspecified address; the `V6` destructure makes any
/// future call with a different address surface as a compile-time
/// error.
fn bind_dual_stack(addr: SocketAddr, only_v6: bool) -> std::io::Result<TcpListener> {
	let SocketAddr::V6(v6) = addr else {
		return Err(std::io::Error::other(
			"bind_dual_stack called with a non-IPv6 address",
		));
	};
	let socket = socket2::Socket::new(
		socket2::Domain::IPV6,
		socket2::Type::STREAM,
		Some(socket2::Protocol::TCP),
	)?;
	socket.set_only_v6(only_v6)?;
	socket.set_reuse_address(true)?;
	socket.bind(&v6.into())?;
	socket.listen(128)?;
	socket.set_nonblocking(true)?;
	let std_listener: std::net::TcpListener = socket.into();
	TcpListener::from_std(std_listener)
}

/// `true` when the address is the IPv6 unspecified address (`::`).
/// The dual-stack setup is IPv6-specific; loopback addresses stay on
/// the plain bind path.
fn is_dual_stack_addr(addr: IpAddr) -> bool {
	matches!(addr, IpAddr::V6(v6) if v6.is_unspecified())
}

/// Helper used by the test: build a fresh `Listener` whose bind
/// shape triggers the dual-stack code path (`::`, port 0). Lives in
/// this module because the test reaches for the same private
/// helpers the production code uses.
#[cfg(test)]
pub(super) fn dual_stack_listener(port: u16) -> Listener {
	Listener {
		kind: ListenerKind::Smtp,
		addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
		port: Some(port),
	}
}

#[cfg(test)]
mod tests;
