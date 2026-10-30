//! HTTPS endpoint for the public MTA-STS policy.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::Tls;
use crate::metrics::Metrics;
use crate::tls::{TlsError, https::FileAcceptor};

const POLICY_PATH: &str = "/.well-known/mta-sts.txt";
const MAX_REQUEST_HEAD: usize = 8 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on concurrent connections to the public MTA-STS listener.
///
/// The endpoint serves a single small text file and the public DNS record is
/// fetched at most once per `max_age` (default one week), so a few hundred
/// concurrent connections covers the burst that a TLS-RPT or DMARC sweep
/// can produce without leaving a backlog the kernel will accept.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// A dedicated HTTPS listener with certificate refresh on new connections.
pub struct Server {
	router: Router,
	tls: FileAcceptor,
	max_connections: usize,
	max_connections_per_ip: usize,
}

impl Server {
	/// Load the initial certificate and restrict file access to `mta-sts.txt`.
	pub fn new(policy_dir: PathBuf, tls: Tls) -> Result<Self, TlsError> {
		Ok(Self {
			router: Router::new()
				.fallback(policy)
				.with_state(policy_dir.join("mta-sts.txt")),
			tls: FileAcceptor::new(tls)?,
			max_connections: DEFAULT_MAX_CONNECTIONS,
			max_connections_per_ip: crate::net::conn_limit::DEFAULT_MTA_STS_CONNECTIONS_PER_IP,
		})
	}

	/// Override the per-listener concurrency cap.
	pub fn with_max_connections(mut self, max: usize) -> Self {
		self.max_connections = max;
		self
	}

	/// Override the per-client concurrency cap.
	pub fn with_max_connections_per_ip(mut self, max: usize) -> Self {
		self.max_connections_per_ip = max;
		self
	}

	/// Serve a bound socket until cancelled; a failed accept does not end it.
	/// Dropping this future aborts its active connections.
	pub async fn serve(self, listener: TcpListener, metrics: Arc<Metrics>) -> io::Result<()> {
		self.serve_on(listener, metrics).await
	}

	/// [`Self::serve`] over any source of connections.
	pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
		mut self,
		listener: A,
		metrics: Arc<Metrics>,
	) -> io::Result<()> {
		let mut accepting = crate::net::accept::Accepting::new(listener);
		// One cap on the listener, one cap per client address, both held
		// inside the connection task until it ends. The same `Admission`
		// pattern the autoconfig TLS branch uses; see `net::conn_limit` for
		// the guard, the /64 grouping and the IPv4-mapped canonicalisation.
		let admission = crate::net::conn_limit::Admission::new(
			self.max_connections,
			self.max_connections_per_ip,
		);
		let mut connections = JoinSet::new();
		loop {
			tokio::select! {
				(stream, peer) = accepting.next() => {
					let peer = crate::net::canonical_peer(peer);
					let admitted = match admission.admit(peer.ip()) {
						Ok(admitted) => admitted,
						Err(why) => {
							tracing::warn!(
								%peer,
								?why,
								"MTA-STS connection limit reached, refusing"
							);
							metrics.mta_sts_connections_dropped();
							drop(stream);
							continue;
						}
					};
					let tls = self.tls.current();
					let router = self.router.clone();
					connections.spawn(async move {
						connection(stream, tls, router, admitted).await;
					});
				}
				Some(_) = connections.join_next(), if !connections.is_empty() => {}
			}
		}
	}
}

async fn connection<S>(
	stream: S,
	tls: TlsAcceptor,
	router: Router,
	_admitted: crate::net::conn_limit::Admitted,
) where
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
		tracing::debug!(%error, "MTA-STS connection ended");
	}
}

async fn policy(State(path): State<PathBuf>, method: Method, uri: Uri) -> Response {
	if uri.path() != POLICY_PATH {
		return StatusCode::NOT_FOUND.into_response();
	}
	if method != Method::GET && method != Method::HEAD {
		return (
			StatusCode::METHOD_NOT_ALLOWED,
			[(header::ALLOW, "GET, HEAD")],
		)
			.into_response();
	}
	let bytes = match tokio::fs::read(&path).await {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			return StatusCode::NOT_FOUND.into_response();
		}
		Err(error) => {
			tracing::warn!(%error, "cannot read MTA-STS policy");
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	};
	let Some(parsed) = std::str::from_utf8(&bytes)
		.ok()
		.and_then(|text| super::policy::parse(text).ok())
	else {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	};
	let length = bytes.len();
	let body = if method == Method::HEAD {
		Body::empty()
	} else {
		Body::from(bytes)
	};
	(
		[
			(
				header::CONTENT_TYPE,
				"text/plain; charset=utf-8".to_string(),
			),
			(header::CACHE_CONTROL, format!("max-age={}", parsed.max_age)),
			(header::CONTENT_LENGTH, length.to_string()),
		],
		body,
	)
		.into_response()
}

#[cfg(test)]
mod tests;
