//! Accept loop of the IMAP listener.
//!
//! [`Server::serve`] and [`Server::serve_on`] share the same body and
//! differ only in the type of the source of connections; the TCP variant
//! is the one the binary calls, the generic one is exercised by tests
//! with an in-memory `Accept`.

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::net::conn_limit::{Admission, refuse};

use super::*;

impl Server {
	/// Accept connections forever.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		self.serve_on(listener).await
	}

	/// [`Self::serve`] over any source of connections.
	pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
		self: Arc<Self>,
		listener: A,
	) -> std::io::Result<()> {
		let admission = Admission::new(self.max_connections, self.max_per_ip);
		let mut accepting = crate::net::accept::Accepting::new(listener);
		loop {
			let (stream, peer) = match &self.drain {
				Some(drain) => tokio::select! {
					accepted = accepting.next() => accepted,
					() = drain.started() => return Ok(()),
				},
				None => accepting.next().await,
			};
			// A dual-stack `::` listener reports an IPv4 peer as
			// `::ffff:a.b.c.d`; canonicalize so the CIDR allowlist the
			// session consults at authentication sees a plain `IpAddr::V4`.
			let peer = crate::net::canonical_peer(peer);
			let admitted = match admission.admit(peer.ip()) {
				Ok(admitted) => admitted,
				Err(why) => {
					tracing::warn!(%peer, ?why, "IMAP connection limit reached, refusing");
					refuse(stream, refusal(why));
					continue;
				}
			};
			let server = Arc::clone(&self);
			let tracked = self.drain.as_ref().map(crate::shutdown::Drain::track);
			tokio::spawn(async move {
				let _admitted = admitted;
				let _tracked = tracked;
				tracing::debug!(%peer, "imap connection accepted");
				if let Err(error) = server.handle(stream, Some(peer.ip())).await {
					tracing::debug!(%peer, %error, "imap connection ended with error");
				}
			});
		}
	}
}
