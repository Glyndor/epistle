//! The STARTTLS upgrade of a running SMTP session. Split from `run.rs` to
//! keep the connection loop under the code-line limit.

use crate::smtp::reply::Reply;
use crate::smtp::session::Session;

use super::{Connection, Server, send};

impl Server {
	/// Answer STARTTLS with `reply` and run the handshake over `stream`.
	/// Returns the encrypted stream, or `None` when TLS is not available and
	/// the session must end (the refusal was already sent). The caller starts
	/// a fresh line decoder: nothing read before the handshake is kept.
	pub(super) async fn upgrade_tls(
		&self,
		mut stream: Box<dyn Connection>,
		session: &mut Session,
		reply: &Reply,
	) -> std::io::Result<Option<Box<dyn Connection>>> {
		let Some(acceptor) = &self.tls else {
			// The session only emits UpgradeTls when TLS was
			// offered; reaching this is a programming error.
			send(&mut stream, &Reply::single(454, "4.7.0 TLS not available")).await?;
			return Ok(None);
		};
		send(&mut stream, reply).await?;
		// Bytes received before the handshake are discarded:
		// a pipelining client cannot smuggle plaintext commands
		// into the TLS session.
		let tls_stream = crate::tls::accept_within(&acceptor.current(), stream).await?;
		// A verified client certificate enables SASL EXTERNAL.
		let identity = tls_stream
			.get_ref()
			.1
			.peer_certificates()
			.and_then(|certs| certs.first())
			.and_then(|cert| crate::tls::identity_from_cert(cert.as_ref()));
		session.set_client_identity(identity);
		session.tls_started();
		// No greeting inside TLS (RFC 3207 section 4.2): the
		// session is back in the state after the 220 banner and
		// the client speaks first with EHLO. A banner here is read
		// as the reply to that EHLO and shifts every later reply.
		Ok(Some(Box::new(tls_stream)))
	}
}
