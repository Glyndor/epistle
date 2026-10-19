//! Admission of connections to a listener: a cap on the whole listener and a
//! cap on what one client can hold of it.
//!
//! The listener cap alone lets one address fill every slot. The per-client
//! cap reuses the SMTP counter, so an IPv4 client is counted by its address
//! and an IPv6 one by its /64. Both are released when the [`Admitted`] guard
//! drops, which happens however the connection task ends: it returns, fails,
//! is cancelled or panics.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::smtp::per_ip::{PerIpCounter, Slot};

/// Concurrent IMAP, POP3 and ManageSieve connections one client may hold on
/// a listener. A rootless Podman bridge shows every client as one address,
/// so the default leaves room for a whole small installation behind it.
pub const DEFAULT_MAILBOX_CONNECTIONS_PER_IP: usize = 200;

/// The same for ManageSieve, whose listener holds 100 connections: a cap of
/// 200 would never act, since one client could not reach it. A script editor
/// keeps one or two connections open, so 40 leaves room for a whole office
/// behind one address and stops one host from taking more than 40% of the
/// listener, the share IMAP and POP3 give at their defaults (200 of 500).
pub const DEFAULT_MANAGESIEVE_CONNECTIONS_PER_IP: usize = 40;

/// Concurrent connections a plain-HTTP listener serves.
pub const DEFAULT_HTTP_CONNECTIONS: usize = 1024;

/// Concurrent connections one client may hold on a plain-HTTP listener.
pub const DEFAULT_HTTP_CONNECTIONS_PER_IP: usize = 256;

/// Concurrent connections one client may hold on the MTA-STS listener. The
/// listener default of 256 is short-lived (the policy is a few hundred
/// bytes and a fetch per `max_age` of up to a week), so 32 leaves room
/// for a single resolver fleet to refetch at the same time without one
/// sweeping address consuming the whole listener.
pub const DEFAULT_MTA_STS_CONNECTIONS_PER_IP: usize = 32;

/// The largest supported connection cap, also safe for semaphore construction.
pub const MAX_CONNECTIONS: usize = 1_000_000;

/// Bound direct callers too, even when configuration validation was bypassed.
pub(crate) fn connection_semaphore(requested: usize) -> Semaphore {
	if requested > MAX_CONNECTIONS {
		tracing::warn!(
			requested,
			maximum = MAX_CONNECTIONS,
			"connection cap exceeds the supported maximum, using the maximum"
		);
	}
	Semaphore::new(requested.min(MAX_CONNECTIONS))
}

/// How long a refusal may take to reach the peer before it is dropped.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// The listener is full.
	ListenerFull,
	/// The client already holds its share.
	ClientFull,
}

/// The two caps of one listener.
pub struct Admission {
	listener: Arc<Semaphore>,
	clients: Arc<PerIpCounter>,
}

/// A connection's claim on the caps; dropping it gives both back.
pub struct Admitted {
	_listener: OwnedSemaphorePermit,
	_client: Slot,
}

impl Admission {
	/// Admit at most `listener` connections, and `per_client` for one client.
	pub fn new(listener: usize, per_client: usize) -> Self {
		Admission {
			listener: Arc::new(connection_semaphore(listener)),
			clients: Arc::new(PerIpCounter::new(per_client)),
		}
	}

	/// Claim a place for a connection from `peer`.
	pub fn admit(&self, peer: IpAddr) -> Result<Admitted, Refusal> {
		let permit = Arc::clone(&self.listener)
			.try_acquire_owned()
			.map_err(|_| Refusal::ListenerFull)?;
		let slot = self
			.clients
			.try_acquire(peer, &[])
			.ok_or(Refusal::ClientFull)?;
		Ok(Admitted {
			_listener: permit,
			_client: slot,
		})
	}

	/// The connections `peer`'s client holds now.
	#[cfg(test)]
	pub fn held_by(&self, peer: IpAddr) -> usize {
		self.clients.count(peer)
	}
}

/// Send `reply` to a refused connection and close it. The write cannot
/// stall the accept loop, and a peer that never reads gives up after two
/// seconds; the reply is small enough to leave in the socket buffer.
pub fn refuse<S>(stream: S, reply: &'static [u8])
where
	S: AsyncWrite + Unpin + Send + 'static,
{
	tokio::spawn(async move {
		let mut stream = stream;
		let _ = tokio::time::timeout(REFUSAL_TIMEOUT, async {
			let _ = stream.write_all(reply).await;
			let _ = stream.flush().await;
			let _ = stream.shutdown().await;
		})
		.await;
	});
}

#[cfg(test)]
#[path = "conn_limit_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "conn_limit_test_support.rs"]
pub(crate) mod test_support;
