//! Serving an axum router over plain HTTP/1.1 with bounds on what one
//! client can hold.
//!
//! `axum::serve` sets no deadline on reading a request head and keeps an
//! idle keep-alive connection open for as long as the client likes, so a
//! client that trickles a header or simply stays connected holds a socket
//! and a task forever (slowloris). Every plain-HTTP listener (the API and
//! JMAP, WebDAV, autoconfig, ACME and metrics) serves through here instead.

use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

/// How long a client gets to send a complete request head. hyper starts
/// this clock whenever it waits for a head, so it also closes a
/// keep-alive connection that sits idle between requests.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest request head accepted, in bytes; a larger one gets 431.
pub const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// Serve `router` on `listener` forever, with the peer address available
/// to handlers as `ConnectInfo<SocketAddr>`.
pub async fn serve(listener: TcpListener, router: Router) -> std::io::Result<()> {
	serve_on(listener, router).await
}

/// [`serve`] over any source of connections.
pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
	listener: A,
	router: Router,
) -> std::io::Result<()> {
	let mut accepting = crate::net::accept::Accepting::new(listener);
	loop {
		let (stream, peer) = accepting.next().await;
		let router = router.clone().layer(axum::Extension(ConnectInfo(peer)));
		tokio::spawn(connection(stream, router));
	}
}

/// Serve one connection until the client closes it or a bound ends it.
/// Upgrades (the JMAP WebSocket) are handed over intact.
async fn connection<S>(stream: S, router: Router)
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let served = http1::Builder::new()
		.max_buf_size(MAX_REQUEST_HEAD)
		.timer(TokioTimer::new())
		.header_read_timeout(HEADER_READ_TIMEOUT)
		.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
		.with_upgrades()
		.await;
	if let Err(error) = served {
		tracing::debug!(%error, "HTTP connection ended");
	}
}

#[cfg(test)]
#[path = "http_serve_tests.rs"]
mod tests;
