//! Serving an axum router over plain HTTP/1.1 with bounds on what one
//! client can hold.
//!
//! `axum::serve` sets no deadline on reading a request head and keeps an
//! idle keep-alive connection open for as long as the client likes, so a
//! client that trickles a header or simply stays connected holds a socket
//! and a task forever (slowloris). Every plain-HTTP listener (the API and
//! JMAP, WebDAV, autoconfig, ACME and metrics) serves through here instead.
//! A request body is held to the bounds of [`super::body_deadline`].

use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use super::conn_limit::{
	Admission, Admitted, DEFAULT_HTTP_CONNECTIONS, DEFAULT_HTTP_CONNECTIONS_PER_IP, refuse,
};

/// How long a client gets to send a complete request head. hyper starts
/// this clock whenever it waits for a head, so it also closes a
/// keep-alive connection that sits idle between requests.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest request head accepted, in bytes; a larger one gets 431.
pub const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// What a plain-HTTP listener sends a connection it has no room for.
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// How many connections a plain-HTTP listener serves, and how many of them
/// one client may hold. An IPv6 client is counted by its /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Connections served at once.
	pub connections: usize,
	/// Connections one client may hold at once.
	pub per_ip: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Limits {
			connections: DEFAULT_HTTP_CONNECTIONS,
			per_ip: DEFAULT_HTTP_CONNECTIONS_PER_IP,
		}
	}
}

/// Serve `router` on `listener` forever, with the peer address available
/// to handlers as `ConnectInfo<SocketAddr>`, under the default [`Limits`].
pub async fn serve(listener: TcpListener, router: Router) -> std::io::Result<()> {
	serve_with(listener, router, Limits::default()).await
}

/// [`serve`] under `limits`.
pub async fn serve_with(
	listener: TcpListener,
	router: Router,
	limits: Limits,
) -> std::io::Result<()> {
	serve_on_with(listener, router, limits).await
}

/// [`serve`] over any source of connections.
#[cfg(test)]
pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
	listener: A,
	router: Router,
) -> std::io::Result<()> {
	serve_on_with(listener, router, Limits::default()).await
}

/// [`serve_with`] over any source of connections. A connection over a limit
/// is answered `503` and closed without reading its request.
pub(crate) async fn serve_on_with<A: crate::net::accept::Accept>(
	listener: A,
	router: Router,
	limits: Limits,
) -> std::io::Result<()> {
	let mut accepting = crate::net::accept::Accepting::new(listener);
	let admission = Admission::new(limits.connections, limits.per_ip);
	loop {
		let (stream, peer) = accepting.next().await;
		let admitted = match admission.admit(peer.ip()) {
			Ok(admitted) => admitted,
			Err(why) => {
				tracing::warn!(%peer, ?why, "HTTP connection limit reached, refusing");
				refuse(stream, BUSY);
				continue;
			}
		};
		let router = router
			.clone()
			.layer(axum::middleware::map_request(
				super::body_deadline::bound_default,
			))
			.layer(axum::Extension(ConnectInfo(peer)));
		tokio::spawn(connection(
			Held {
				stream,
				_admitted: admitted,
			},
			router,
		));
	}
}

/// A stream that keeps its [`Admitted`] places for as long as it lives. An
/// upgraded connection (the JMAP WebSocket) outlives the future that serves
/// the HTTP part, so the places travel inside the stream hyper hands over.
struct Held<S> {
	stream: S,
	_admitted: Admitted,
}

impl<S: AsyncRead + Unpin> AsyncRead for Held<S> {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Held<S> {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
	}

	fn poll_flush(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.stream).poll_flush(cx)
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
	}

	fn poll_write_vectored(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> std::task::Poll<std::io::Result<usize>> {
		std::pin::Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
	}

	fn is_write_vectored(&self) -> bool {
		self.stream.is_write_vectored()
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
