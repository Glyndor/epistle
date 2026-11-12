//! Hostile remote peers. LDAP and S3 exercise the existing backends, since
//! migrate currently has no LDAP/S3 remote import clients. Each peer is a
//! loopback fake; a case must end in an error, with bounded memory and time.

mod ldap;
mod s3;

use std::time::Duration;

pub(super) const DEADLINE: Duration = Duration::from_secs(3);

/// Keep every fake bounded even when an assertion unwinds.
pub(super) struct Peer(pub(super) tokio::task::JoinHandle<()>);

impl Drop for Peer {
	fn drop(&mut self) {
		self.0.abort();
	}
}
