//! Serving loop for the autoconfig listener, over TLS or plain HTTP.
//!
//! Mail clients fetch their setup from `https://autoconfig.<domain>/` and
//! `https://autodiscover.<domain>/` on port 443. With an acceptor the listener
//! terminates TLS itself, so no proxy is needed in front of it; without one it
//! speaks plain HTTP for operators who keep their own TLS proxy.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

/// The documents fit in a few kilobytes and requests carry only a query
/// string, so a small request head is plenty.
const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// Upper bound on one connection, handshake included, so a client that
/// stalls cannot hold a slot.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve `router` on `listener`; a failed accept does not end it. With `tls` every
/// connection is a TLS handshake followed by HTTP/1.1; without it the router
/// is served as plain HTTP. At most `max_connections` TLS connections run at
/// once; extra ones are closed straight away.
pub async fn serve(
	listener: TcpListener,
	router: Router,
	tls: Option<TlsAcceptor>,
	max_connections: usize,
	plain: crate::net::http_serve::Limits,
) -> io::Result<()> {
	serve_on(listener, router, tls, max_connections, plain).await
}

/// [`serve`] over any source of connections.
pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
	listener: A,
	router: Router,
	tls: Option<TlsAcceptor>,
	max_connections: usize,
	plain: crate::net::http_serve::Limits,
) -> io::Result<()> {
	let Some(tls) = tls else {
		return crate::net::http_serve::serve_on_with(listener, router, plain).await;
	};
	// A cap of 0 means "the default": a semaphore of 0 would refuse them all.
	let max_connections = match max_connections {
		0 => crate::net::conn_limit::DEFAULT_HTTP_CONNECTIONS,
		cap => cap,
	};
	let mut accepting = crate::net::accept::Accepting::new(listener);
	let semaphore = Arc::new(Semaphore::new(max_connections));
	let mut connections = JoinSet::new();
	loop {
		tokio::select! {
			(stream, _) = accepting.next() => {
				let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
					drop(stream);
					continue;
				};
				let tls = tls.clone();
				let router = router.clone();
				connections.spawn(async move {
					connection(stream, tls, router).await;
					drop(permit);
				});
			}
			Some(_) = connections.join_next(), if !connections.is_empty() => {}
		}
	}
}

async fn connection<S>(stream: S, tls: TlsAcceptor, router: Router)
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let work = async {
		let stream = tls.accept(stream).await.map_err(io::Error::other)?;
		http1::Builder::new()
			.max_buf_size(MAX_REQUEST_HEAD)
			.timer(TokioTimer::new())
			.header_read_timeout(CONNECTION_TIMEOUT)
			.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
			.await
			.map_err(io::Error::other)
	};
	if let Ok(Err(error)) = tokio::time::timeout(CONNECTION_TIMEOUT, work).await {
		tracing::debug!(%error, "autoconfig connection ended");
	}
}
