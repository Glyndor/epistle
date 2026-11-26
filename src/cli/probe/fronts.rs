//! The probe of a stack that runs fronts: the listeners that serve the API are
//! Unix sockets, which nothing dials over TCP, so each is asked `GET /healthz`
//! on its socket. The other listeners are probed as before.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use super::{PROBE_TIMEOUT, ProbeLine};
use crate::config::Config;

/// What a front writes before any request it forwards, which the core refuses
/// a request without.
const REQUEST: &[u8] =
	b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nX-Epistle-Peer: 127.0.0.1\r\nConnection: close\r\n\r\n";

/// One probe line for each listener that serves the API.
pub(super) async fn probe_sockets(config: &Config) -> Vec<ProbeLine> {
	let mut lines = Vec::new();
	for listener in config
		.listeners
		.iter()
		.filter(|listener| listener.kind.serves_api())
	{
		let socket = crate::api::front_socket::path(&config.data_dir, listener.kind);
		let outcome = match timeout(PROBE_TIMEOUT, healthz(&socket)).await {
			Ok(outcome) => outcome,
			Err(_) => Err("timeout".to_string()),
		};
		lines.push(ProbeLine {
			kind: listener.kind.as_str(),
			addr: socket.display().to_string(),
			ok: outcome.is_ok(),
			error: outcome.err(),
			warning: None,
		});
	}
	lines
}

/// `GET /healthz` over the socket at `path`: `200` or a reason.
async fn healthz(path: &std::path::Path) -> Result<(), String> {
	let mut stream = UnixStream::connect(path)
		.await
		.map_err(|error| format!("connect: {error}"))?;
	stream
		.write_all(REQUEST)
		.await
		.map_err(|error| format!("write probe request: {error}"))?;
	let mut head = Vec::new();
	let mut buffer = [0u8; 64];
	while !head.contains(&b'\n') && head.len() < 512 {
		let read = stream
			.read(&mut buffer)
			.await
			.map_err(|error| format!("read probe answer: {error}"))?;
		if read == 0 {
			break;
		}
		head.extend_from_slice(&buffer[..read]);
	}
	let line = String::from_utf8_lossy(&head);
	let status = line.lines().next().unwrap_or_default();
	let mut parts = status.split_whitespace();
	match (parts.next(), parts.next()) {
		(Some(version), Some("200")) if version.starts_with("HTTP/") => Ok(()),
		_ => Err(format!("expected 200 from /healthz, got {status:?}")),
	}
}
