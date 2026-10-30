//! Bounded raw-wire clients and an isolated production listener per test.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use epistle::directory_store::DirectoryHandle;
use epistle::smtp::directory::Directory;
use epistle::smtp::server::Server;
use epistle::smtp::sink::MemorySink;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::common::BANNER_READ_DEADLINE;

pub const OK: &str = "250 2.0.0 ok\r\n";
pub const SYNTAX: &str = "500 5.5.2 syntax error\r\n";
pub const BAD_ARGS: &str = "501 5.5.4 invalid arguments\r\n";
pub const BARE: &str = "554 5.5.2 bare CR or LF is not allowed, closing connection\r\n";
pub const LONG: &str = "500 5.5.2 line too long, closing connection\r\n";
pub const TIME_UP: &str = "421 4.4.2 session time limit reached\r\n";
pub const BODY: &[u8] = b"From: sender@remote.test\r\nSubject: legitimate\r\n\r\nbody\r\n.\r\n";

pub struct AbortOnDrop(pub tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

pub struct Harness {
	pub addr: SocketAddr,
	pub sink: Arc<MemorySink>,
	_task: AbortOnDrop,
}

pub fn directory() -> Directory {
	Directory::new(
		["epistle.test".to_string()],
		[("tester@epistle.test".to_string(), "tester".to_string())],
	)
}

impl Harness {
	pub async fn start(configure: impl FnOnce(Server) -> Server) -> Self {
		Self::with_directory(directory(), configure).await
	}

	pub async fn with_directory(
		directory: Directory,
		configure: impl FnOnce(Server) -> Server,
	) -> Self {
		let sink = Arc::new(MemorySink::new());
		let server = configure(
			Server::new("mx.epistle.test", sink.clone())
				.with_directory(DirectoryHandle::new(directory)),
		);
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind smtp");
		let addr = listener.local_addr().expect("listener address");
		let task = tokio::spawn(Arc::new(server).serve(listener));
		Self {
			addr,
			sink,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub async fn connect(&self) -> TcpStream {
		let mut client = timeout(BANNER_READ_DEADLINE, TcpStream::connect(self.addr))
			.await
			.expect("connect deadline")
			.expect("connect smtp");
		client.set_nodelay(true).expect("disable Nagle");
		expect(&mut client, "220 mx.epistle.test ESMTP ready\r\n").await;
		client
	}

	/// Use a new connection to the same listener after every attack.
	pub async fn healthy(&self) {
		let mut client = self.connect().await;
		helo(&mut client).await;
		send(&mut client, b"NOOP\r\n").await;
		expect(&mut client, OK).await;
		quit(&mut client).await;
	}
}

pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
	timeout(BANNER_READ_DEADLINE, stream.write_all(bytes))
		.await
		.expect("write deadline")
		.expect("write smtp");
}

/// Keep CRLF verbatim and never read beyond the next reply.
pub async fn line<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<String>> {
	timeout(BANNER_READ_DEADLINE, async {
		let mut bytes = Vec::new();
		loop {
			let mut byte = [0];
			match stream.read(&mut byte).await {
				Ok(0) if bytes.is_empty() => return Ok(None),
				Ok(0) => panic!("closed mid-reply: {bytes:?}"),
				Ok(_) => bytes.push(byte[0]),
				Err(e) => return Err(e),
			}
			assert!(bytes.len() <= 4096, "unbounded reply");
			if bytes.ends_with(b"\r\n") {
				return Ok(Some(String::from_utf8(bytes).expect("ASCII reply")));
			}
		}
	})
	.await
	.expect("reply deadline")
}

pub async fn expect<S: AsyncRead + Unpin>(stream: &mut S, expected: &str) {
	assert_eq!(
		line(stream).await.expect("read reply").as_deref(),
		Some(expected)
	);
}

pub async fn closed<S: AsyncRead + Unpin>(stream: &mut S) {
	match line(stream).await {
		Ok(None) => {}
		Err(e)
			if matches!(
				e.kind(),
				io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
			) => {}
		other => panic!("expected connection close, got {other:?}"),
	}
}

pub async fn helo<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"HELO client.remote.test\r\n").await;
	expect(stream, "250 mx.epistle.test\r\n").await;
}

pub async fn ehlo<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"EHLO client.remote.test\r\n").await;
	for _ in 0..32 {
		let reply = line(stream).await.expect("EHLO reply").expect("EHLO open");
		assert!(reply.starts_with("250"), "EHLO: {reply:?}");
		match reply.as_bytes().get(3) {
			Some(b' ') => return,
			Some(b'-') => {}
			_ => panic!("malformed EHLO: {reply:?}"),
		}
	}
	panic!("unbounded EHLO capabilities");
}

pub async fn envelope<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"MAIL FROM:<sender@remote.test>\r\n").await;
	expect(stream, OK).await;
	send(stream, b"RCPT TO:<tester@epistle.test>\r\n").await;
	expect(stream, OK).await;
}

pub async fn data<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	envelope(stream).await;
	send(stream, b"DATA\r\n").await;
	expect(stream, "354 start mail input, end with <CRLF>.<CRLF>\r\n").await;
}

pub async fn quit<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
	send(stream, b"QUIT\r\n").await;
	expect(stream, "221 2.0.0 closing connection\r\n").await;
	closed(stream).await;
}

pub const SHORT_SESSION: Duration = Duration::from_secs(2);

/// A password minted when the test starts, so no credential sits in the source.
pub struct Password;

pub static PASSWORD: Password = Password;

impl Password {
	fn minted() -> &'static str {
		static VALUE: std::sync::LazyLock<String> =
			std::sync::LazyLock::new(|| format!("Fx1!{}", uuid::Uuid::new_v4().simple()));
		VALUE.as_str()
	}
}

impl std::ops::Deref for Password {
	type Target = str;

	fn deref(&self) -> &str {
		Self::minted()
	}
}

impl std::fmt::Display for Password {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(Self::minted())
	}
}
