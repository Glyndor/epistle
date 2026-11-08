//! The POP3S and ManageSieve listeners: both TLS-only servers over the
//! account directory and the data directory.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;

use super::connection_limits::MailboxLimits;
use super::tasks::ListenerTask;

fn require(acceptor: Option<&TlsAcceptor>, what: &str) -> std::io::Result<TlsAcceptor> {
	acceptor
		.cloned()
		.ok_or_else(|| std::io::Error::other(format!("{what} listener without TLS configured")))
}

/// Serve POP3S (implicit TLS) on `listener`.
///
/// The serving future is returned, not spawned: `serve` starts it once the
/// privileges are dropped.
pub(super) fn pop3s(
	listener: TcpListener,
	data_dir: PathBuf,
	directory: DirectoryHandle,
	acceptor: Option<&TlsAcceptor>,
	crypto: crate::storage::MessageCrypto,
	max_conn: usize,
	limits: &MailboxLimits,
) -> std::io::Result<ListenerTask> {
	let server = crate::pop3::server::Server::new(data_dir, directory, require(acceptor, "POP3S")?)
		.with_crypto(crypto)
		.with_max_connections(max_conn)
		.with_max_connections_per_ip(limits.per_ip)
		.with_preauth_timeout(limits.preauth_timeout)
		.with_per_account_counter(Arc::clone(&limits.per_account_counter));
	let server = Arc::new(server);
	Ok(Box::pin(server.serve(listener)))
}

/// Serve ManageSieve on `listener`.
///
/// The serving future is returned, not spawned: `serve` starts it once the
/// privileges are dropped.
pub(super) fn managesieve(
	listener: TcpListener,
	data_dir: PathBuf,
	directory: DirectoryHandle,
	acceptor: Option<&TlsAcceptor>,
	max_conn: usize,
	limits: &MailboxLimits,
) -> std::io::Result<ListenerTask> {
	let server = Arc::new(
		crate::managesieve::server::Server::new(
			data_dir,
			directory,
			require(acceptor, "ManageSieve")?,
		)
		.with_max_connections(max_conn)
		.with_max_connections_per_ip(limits.managesieve_per_ip)
		.with_preauth_timeout(limits.preauth_timeout),
	);
	Ok(Box::pin(server.serve(listener)))
}
