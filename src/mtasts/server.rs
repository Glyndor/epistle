//! HTTPS endpoint for the public MTA-STS policy.

use std::io;
use std::path::PathBuf;
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
use crate::tls::{TlsError, https::FileAcceptor};

const POLICY_PATH: &str = "/.well-known/mta-sts.txt";
const MAX_REQUEST_HEAD: usize = 8 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// A dedicated HTTPS listener with certificate refresh on new connections.
pub struct Server {
	router: Router,
	tls: FileAcceptor,
}

impl Server {
	/// Load the initial certificate and restrict file access to `mta-sts.txt`.
	pub fn new(policy_dir: PathBuf, tls: Tls) -> Result<Self, TlsError> {
		Ok(Self {
			router: Router::new()
				.fallback(policy)
				.with_state(policy_dir.join("mta-sts.txt")),
			tls: FileAcceptor::new(tls)?,
		})
	}

	/// Serve a bound socket until cancelled or an accept error occurs.
	/// Dropping this future aborts its active connections.
	pub async fn serve(mut self, listener: TcpListener) -> io::Result<()> {
		let mut connections = JoinSet::new();
		loop {
			tokio::select! {
				accepted = listener.accept() => {
					let (stream, _) = accepted?;
					let tls = self.tls.current();
					let router = self.router.clone();
					connections.spawn(connection(stream, tls, router));
				}
				Some(_) = connections.join_next(), if !connections.is_empty() => {}
			}
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
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_http.rs"]
mod tests_http;
