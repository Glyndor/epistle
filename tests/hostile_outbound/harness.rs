//! Bounded peers, independent watchdogs and counted DNS answers.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use epistle::config::OutboundTls;
use epistle::dane::rrset::TlsaRrset;
use epistle::queue::client::{DeliveryError, deliver};
use epistle::spf::{DnsFailure, DnsLookup};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::time::timeout;

pub const WATCHDOG: Duration = Duration::from_secs(20);
pub const BODY: &[u8] = b"From: sender@outside.test\r\nSubject: legitimate\r\n\r\nbody\r\n";
pub type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

pub struct AbortOnDrop(pub tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

/// A synchronous parser cannot block this independent watchdog's clock.
pub fn bounded<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
	let (send, recv) = std::sync::mpsc::sync_channel(1);
	let task = std::thread::spawn(move || {
		let result = work();
		let _ = send.send(result);
	});
	let result = recv.recv_timeout(WATCHDOG).expect("parser panic or hang");
	task.join().expect("parser thread panicked");
	result
}

pub async fn within<T>(work: impl Future<Output = T>) -> T {
	timeout(WATCHDOG, work).await.expect("peer/client watchdog")
}

pub async fn line<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
	let mut out = Vec::new();
	loop {
		let byte = stream.read_u8().await.expect("peer command");
		out.push(byte);
		assert!(out.len() <= 8192, "unbounded peer capture");
		if out.ends_with(b"\r\n") {
			return out;
		}
	}
}

pub async fn write<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
	stream.write_all(bytes).await.expect("peer write");
}

pub async fn delivery(
	stream: DuplexStream,
	sender: &str,
	recipients: &[String],
	data: &[u8],
) -> Result<(), DeliveryError> {
	deliver(
		stream,
		"mx.outside.test",
		"mail.epistle.test",
		sender,
		recipients,
		data,
		false,
		None,
		&TlsaRrset::Absent,
		OutboundTls::Strict,
		&mut None,
	)
	.await
}

pub fn recipient() -> Vec<String> {
	vec!["victim@outside.test".into()]
}

pub async fn envelope(peer: &mut DuplexStream) {
	write(peer, b"220 destination ESMTP\r\n").await;
	assert_eq!(line(peer).await, b"EHLO mail.epistle.test\r\n");
	write(peer, b"250 destination\r\n").await;
	assert_eq!(line(peer).await, b"MAIL FROM:<sender@outside.test>\r\n");
	write(peer, b"250 sender ok\r\n").await;
	assert_eq!(line(peer).await, b"RCPT TO:<victim@outside.test>\r\n");
	write(peer, b"250 recipient ok\r\n").await;
	assert_eq!(line(peer).await, b"DATA\r\n");
	write(peer, b"354 send data\r\n").await;
}

pub async fn healthy() {
	let (client, mut peer) = tokio::io::duplex(4096);
	let recipients = recipient();
	let remote = async {
		envelope(&mut peer).await;
		let mut data = Vec::new();
		loop {
			let next = line(&mut peer).await;
			if next == b".\r\n" {
				break;
			}
			data.extend(next);
			assert!(data.len() < 8192);
		}
		assert_eq!(data, BODY);
		write(&mut peer, b"250 accepted\r\n").await;
		assert_eq!(line(&mut peer).await, b"QUIT\r\n");
		write(&mut peer, b"221 bye\r\n").await;
	};
	let (result, ()) = within(async {
		tokio::join!(
			delivery(client, "sender@outside.test", &recipients, BODY),
			remote
		)
	})
	.await;
	assert_eq!(result, Ok(()));
}

pub struct HttpPeer {
	pub addr: SocketAddr,
	pub hits: Arc<AtomicUsize>,
	_task: AbortOnDrop,
}

impl HttpPeer {
	/// Reply after a bounded header read, then retain the socket if requested.
	pub async fn start(response: Vec<u8>, hold: bool) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind HTTP");
		let addr = listener.local_addr().expect("HTTP address");
		let hits = Arc::new(AtomicUsize::new(0));
		let counter = hits.clone();
		let task = tokio::spawn(async move {
			loop {
				let (mut stream, _) = listener.accept().await.expect("accept HTTP");
				let mut headers = Vec::new();
				while !headers.ends_with(b"\r\n\r\n") {
					headers.push(stream.read_u8().await.expect("HTTP request"));
					assert!(headers.len() <= 8192);
				}
				let headers = String::from_utf8(headers).expect("ASCII request headers");
				let length = headers
					.lines()
					.filter_map(|line| line.split_once(':'))
					.find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
					.map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
					.expect("webhook request has a known body length");
				assert!(length <= 8192, "bounded request body capture");
				let mut body = vec![0; length];
				stream
					.read_exact(&mut body)
					.await
					.expect("HTTP request body");
				counter.fetch_add(1, Ordering::SeqCst);
				// A rejected giant response may close before the peer finishes.
				let _ = stream.write_all(&response).await;
				if hold {
					std::future::pending::<()>().await;
				}
			}
		});
		Self {
			addr,
			hits,
			_task: AbortOnDrop(task.abort_handle()),
		}
	}

	pub fn url(&self) -> String {
		format!("http://{}/hook", self.addr)
	}

	pub fn count(&self) -> usize {
		self.hits.load(Ordering::SeqCst)
	}
}

#[derive(Default)]
pub struct Dns {
	pub records: BTreeMap<String, Vec<String>>,
	pub queries: AtomicUsize,
	pub addresses: AtomicUsize,
}

impl Dns {
	pub fn with(mut self, name: &str, record: &str) -> Self {
		self.records
			.entry(name.into())
			.or_default()
			.push(record.into());
		self
	}

	pub fn count(&self) -> usize {
		self.queries.load(Ordering::SeqCst)
	}
}

impl DnsLookup for Dns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let count = self.queries.fetch_add(1, Ordering::SeqCst);
		assert!(count < 64, "unbounded DNS recursion");
		let answer = self.records.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(answer) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<IpAddr>> {
		self.addresses.fetch_add(1, Ordering::SeqCst);
		Box::pin(async { Ok(vec!["192.0.2.2".parse().expect("documentation IP")]) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		panic!("unexpected MX query");
	}
}
