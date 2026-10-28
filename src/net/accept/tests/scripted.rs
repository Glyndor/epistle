use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;

use tokio::io::DuplexStream;

/// Hands out its scripted results in order, then waits forever.
pub(crate) struct Scripted(Mutex<VecDeque<std::io::Result<DuplexStream>>>);

/// A listener that first fails with each of `errors` (raw OS error
/// numbers), then accepts one connection whose client end is returned.
pub(crate) fn failing_then_connecting(errors: &[i32]) -> (Scripted, DuplexStream) {
	let (client, server) = tokio::io::duplex(64 * 1024);
	let mut script: VecDeque<_> = errors
		.iter()
		.map(|&code| Err(std::io::Error::from_raw_os_error(code)))
		.collect();
	script.push_back(Ok(server));
	(Scripted(Mutex::new(script)), client)
}

impl super::Accept for Scripted {
	type Stream = DuplexStream;

	fn accept(&self) -> impl Future<Output = std::io::Result<(DuplexStream, SocketAddr)>> + Send {
		let next = self.0.lock().expect("script").pop_front();
		async move {
			match next {
				Some(result) => {
					result.map(|stream| (stream, "192.0.2.1:4000".parse().expect("addr")))
				}
				None => std::future::pending().await,
			}
		}
	}
}
