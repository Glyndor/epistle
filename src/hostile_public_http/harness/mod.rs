use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

mod panic;
mod tls;
mod transport;
use panic::PanicWatch;
pub(super) use tls::{Certificate, TlsClient};
use transport::{Stream, tcp_mode};

pub const LIMIT: usize = 16 * 1024;
pub const DEADLINE: Duration = Duration::from_secs(5);

pub struct Incoming {
	listener: Option<tokio::net::TcpListener>,
	receiver: Mutex<mpsc::Receiver<Stream>>,
}

impl crate::net::accept::Accept for Incoming {
	type Stream = Stream;

	async fn accept(&self) -> io::Result<(Stream, SocketAddr)> {
		if let Some(listener) = &self.listener {
			let (stream, peer) = listener.accept().await?;
			return Ok((Box::new(stream), peer));
		}
		let stream = self
			.receiver
			.lock()
			.await
			.recv()
			.await
			.expect("fixture sender");
		Ok((stream, "192.0.2.4:12345".parse().expect("peer")))
	}
}

/// Owns the accept loop; every exchange checks that it has not terminated.
/// Drop cancels it even when an assertion unwinds.
pub struct Peer {
	addr: Option<SocketAddr>,
	sender: mpsc::Sender<Stream>,
	task: JoinHandle<io::Result<()>>,
	watch: PanicWatch,
}

impl Peer {
	pub fn start<F, R>(serve: F) -> Self
	where
		F: FnOnce(Incoming) -> R,
		R: Future<Output = io::Result<()>> + Send + 'static,
	{
		let listener = tcp_mode().then(|| {
			let listener = std::net::TcpListener::bind("127.0.0.1:0")
				.expect("TCP mode requires socket access");
			listener
				.set_nonblocking(true)
				.expect("nonblocking listener");
			tokio::net::TcpListener::from_std(listener).expect("Tokio listener")
		});
		let addr = listener
			.as_ref()
			.map(|s| s.local_addr().expect("listener address"));
		let (sender, receiver) = mpsc::channel(8);
		let watch = PanicWatch::new();
		let task = tokio::spawn(serve(Incoming {
			listener,
			receiver: Mutex::new(receiver),
		}));
		Self {
			addr,
			sender,
			task,
			watch,
		}
	}

	pub async fn connect(&self) -> Stream {
		assert!(
			!self.task.is_finished(),
			"public listener exited or panicked"
		);
		assert!(
			!self.watch.panicked.load(Ordering::SeqCst),
			"public connection panicked"
		);
		if let Some(addr) = self.addr {
			return Box::new(
				timeout(DEADLINE, tokio::net::TcpStream::connect(addr))
					.await
					.expect("connect deadline")
					.expect("TCP connect"),
			);
		}
		let (client, server) = tokio::io::duplex(LIMIT * 2);
		timeout(DEADLINE, self.sender.send(Box::new(server)))
			.await
			.expect("accept deadline")
			.expect("listener alive");
		Box::new(client)
	}

	pub async fn healthy<S: AsyncRead + AsyncWrite + Unpin>(
		&self,
		stream: S,
		path: &str,
		marker: &str,
	) {
		let reply = exchange(stream, &request(path, "mail.example.org")).await;
		assert_status(&reply, 200);
		assert!(
			reply.contains(marker),
			"health response lost fixture content"
		);
		assert!(
			!self.task.is_finished(),
			"listener exited after hostile request"
		);
		assert!(
			!self.watch.panicked.load(Ordering::SeqCst),
			"public connection panicked"
		);
	}
}

impl Drop for Peer {
	fn drop(&mut self) {
		self.task.abort();
	}
}

pub fn request(path: &str, host: &str) -> String {
	format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

pub fn assert_status(reply: &str, status: u16) {
	assert!(
		reply.starts_with(&format!("HTTP/1.1 {status} ")),
		"unexpected HTTP status: {reply:?}"
	);
}

pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &str) -> String {
	timeout(DEADLINE, async {
		stream
			.write_all(request.as_bytes())
			.await
			.expect("request write");
		let mut bytes = Vec::new();
		stream
			.take((LIMIT + 1) as u64)
			.read_to_end(&mut bytes)
			.await
			.expect("response read");
		assert!(bytes.len() <= LIMIT, "unbounded public response");
		String::from_utf8(bytes).expect("UTF-8 public response")
	})
	.await
	.expect("public response deadline")
}

/// Keep a head incomplete, but active, beyond the 30-second production bound.
/// A reset-on-each-byte idle timer would survive all 36 drips and fail here.
/// Paused Tokio time keeps this test fast; no artificial timeout is installed
/// on the server side. TLS may close transport without a close_notify.
pub async fn slowloris<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, path: &str) {
	if !tcp_mode() {
		tokio::time::pause();
	}
	let started = Instant::now();
	stream
		.write_all(format!("GET {path} HTTP/1.1\r\nHost: mail.example.org\r\nX-Drip: ").as_bytes())
		.await
		.expect("partial head");
	let (mut reader, mut writer) = tokio::io::split(stream);
	let drip = async {
		for _ in 0..36 {
			tokio::time::sleep(Duration::from_secs(1)).await;
			// The reader establishes closure; a failed write must not race it.
			let _ = writer.write_all(b"x").await;
		}
	};
	let read = async {
		let mut bytes = Vec::new();
		let result = (&mut reader)
			.take((LIMIT + 1) as u64)
			.read_to_end(&mut bytes)
			.await;
		assert!(bytes.len() <= LIMIT, "unbounded slowloris response");
		if let Err(error) = result {
			assert_eq!(
				error.kind(),
				io::ErrorKind::UnexpectedEof,
				"unexpected close reason"
			);
		}
		assert!(
			bytes.is_empty() || bytes.starts_with(b"HTTP/1.1 408 "),
			"unexpected slowloris response: {bytes:?}"
		);
	};
	timeout(Duration::from_secs(35), async {
		tokio::select! {
			() = read => {},
			() = drip => panic!("dripping peer outlived request-head deadline"),
		}
	})
	.await
	.expect("slowloris connection was not closed within 35 seconds");
	assert!(
		started.elapsed() >= Duration::from_secs(29),
		"premature close could hide a panic"
	);
	if !tcp_mode() {
		tokio::time::resume();
	}
}
