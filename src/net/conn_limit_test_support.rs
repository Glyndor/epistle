//! Helpers for the tests that drive a listener over a real socket and count
//! what it admits and what it refuses.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// How long a server gets to refuse a connection before it counts as
/// admitted. Real time: these tests use real sockets.
const SETTLE: Duration = Duration::from_millis(300);

/// What a new connection met.
pub enum Outcome {
	/// The server kept the connection; whatever it sent first is in `greeting`.
	Admitted {
		_stream: TcpStream,
		greeting: String,
	},
	/// The server answered and closed.
	Refused(String),
}

impl Outcome {
	/// The refusal text, or `None` when the connection was admitted.
	pub fn refusal(&self) -> Option<&str> {
		match self {
			Outcome::Refused(text) => Some(text),
			Outcome::Admitted { .. } => None,
		}
	}
}

/// Connect to `addr` and see whether the server admits or refuses it.
pub async fn connect(addr: SocketAddr) -> Outcome {
	let mut stream = TcpStream::connect(addr).await.expect("connect");
	let mut seen = Vec::new();
	let closed = tokio::time::timeout(SETTLE, stream.read_to_end(&mut seen)).await;
	let text = String::from_utf8_lossy(&seen).into_owned();
	match closed {
		Ok(_) => Outcome::Refused(text),
		Err(_) => Outcome::Admitted {
			_stream: stream,
			greeting: text,
		},
	}
}

/// Connect until the server admits a connection (a place was given back), or
/// panic after five seconds.
pub async fn connect_when_a_place_frees(addr: SocketAddr) -> Outcome {
	let start = std::time::Instant::now();
	loop {
		let outcome = connect(addr).await;
		if outcome.refusal().is_none() {
			return outcome;
		}
		assert!(
			start.elapsed() < Duration::from_secs(5),
			"no place was given back"
		);
	}
}
