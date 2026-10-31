//! Independent client codec and process watchdog for hostile inflation.

use std::future::Future;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use super::harness::*;

pub fn deflate(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = Compress::new(Compression::best(), false);
	let mut out = vec![0; bytes.len() + 4096];
	encoder
		.compress(bytes, &mut out, FlushCompress::Sync)
		.expect("raw DEFLATE fixture");
	assert_eq!(encoder.total_in(), bytes.len() as u64);
	out.truncate(encoder.total_out() as usize);
	out
}

/// Read bytewise so no compressed bytes belonging to the next reply are lost.
pub struct Replies(Decompress);

impl Replies {
	pub fn new() -> Self {
		Self(Decompress::new(false))
	}

	pub async fn expect(&mut self, stream: &mut (impl AsyncRead + Unpin), expected: &str) {
		timeout(IO_DEADLINE, async {
			let mut plain = Vec::new();
			let mut raw = Vec::new();
			// Consume the sync-flush trailer too, so a later raw EOF check
			// cannot mistake it for unexpected application bytes.
			while !plain.ends_with(b"\r\n") || !raw.ends_with(&[0, 0, 255, 255]) {
				let mut byte = [0];
				stream
					.read_exact(&mut byte)
					.await
					.expect("compressed reply");
				raw.push(byte[0]);
				assert!(raw.len() <= 8192, "unbounded compressed reply");
				let before = self.0.total_out();
				let consumed = self.0.total_in();
				let mut out = [0; 4096];
				self.0
					.decompress(&byte, &mut out, FlushDecompress::None)
					.expect("valid compressed reply");
				assert_eq!(self.0.total_in() - consumed, 1);
				plain.extend_from_slice(&out[..(self.0.total_out() - before) as usize]);
				assert!(plain.len() <= 4096, "unbounded inflated reply");
			}
			assert_eq!(plain, expected.as_bytes());
		})
		.await
		.expect("compressed reply deadline");
	}
}

pub fn empty_inbox(server: &Harness) {
	assert!(
		epistle::imap::mailbox::Snapshot::open(
			server.data.path(),
			"tester",
			"INBOX",
			&epistle::storage::MessageCrypto::disabled(),
		)
		.expect("inbox snapshot")
		.is_empty(),
		"hostile compressed input stored a message"
	);
}

struct Reap(Child);

impl Drop for Reap {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

/// A Tokio timeout cannot interrupt a codec spinning inside poll_read.
/// The parent runs outside the attacked runtime and kills/reaps on failure.
pub fn watched(name: &str, attack: impl Future<Output = ()>) {
	const CHILD: &str = "EPISTLE_COMPRESS_CHILD";
	if std::env::var(CHILD).as_deref() == Ok(name) {
		tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("attack runtime")
			.block_on(attack);
		return;
	}
	let output = tempfile::NamedTempFile::new().expect("child output");
	let mut child = Reap(
		Command::new(std::env::current_exe().expect("test executable"))
			.args(["--exact", name, "--nocapture"])
			.env(CHILD, name)
			.stdout(Stdio::from(output.as_file().try_clone().expect("stdout")))
			.stderr(Stdio::from(output.as_file().try_clone().expect("stderr")))
			.spawn()
			.expect("watchdog child"),
	);
	let start = Instant::now();
	loop {
		if let Some(status) = child.0.try_wait().expect("child status") {
			let log = std::fs::read_to_string(output.path()).expect("child log");
			assert!(status.success(), "{name}: {status}\n{log}");
			break;
		}
		assert!(
			start.elapsed() < Duration::from_secs(25),
			"{name}: work deadline"
		);
		// Linux exposes resident memory independently of allocator internals.
		#[cfg(target_os = "linux")]
		if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", child.0.id()))
			&& let Some(rss) = status.lines().find_map(|line| {
				line.strip_prefix("VmRSS:")?
					.split_whitespace()
					.next()?
					.parse::<usize>()
					.ok()
			}) {
			assert!(rss < 256 * 1024, "{name}: resident memory exceeded 256 MiB");
		}
		std::thread::sleep(Duration::from_millis(20));
	}
}

/// Exercise the public production connection loop without requiring a socket.
/// Duplex capacity also makes a single coalesced write deterministic.
pub async fn memory_authenticated() -> (
	tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
	tempfile::TempDir,
	AbortOnDrop,
) {
	use epistle::directory_store::DirectoryHandle;
	use epistle::imap::server::{Server, TlsMode};
	use epistle::smtp::directory::Directory;
	use std::sync::Arc;
	use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

	epistle::tls::ensure_crypto_provider();
	let cert =
		rcgen::generate_simple_self_signed(vec!["mail.epistle.test".into()]).expect("certificate");
	let acceptor = epistle::tls::acceptor_from_pem(
		cert.cert.pem().as_bytes(),
		cert.signing_key.serialize_pem().as_bytes(),
	)
	.expect("acceptor");
	let mut roots = RootCertStore::empty();
	roots
		.add(cert.cert.der().clone())
		.expect("trust certificate");
	let connector = tokio_rustls::TlsConnector::from(Arc::new(
		ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth(),
	));
	let directory = Directory::new(
		["epistle.test".to_string()],
		[("tester@epistle.test".to_string(), "tester".to_string())],
	)
	.with_password_hashes([(
		"tester".to_string(),
		epistle::smtp::auth::hash_password(&PASSWORD).expect("password hash"),
	)]);
	let data = tempfile::tempdir().expect("mail store");
	let server = Server::new(
		"mail.epistle.test",
		data.path().to_path_buf(),
		DirectoryHandle::new(directory),
		acceptor,
		TlsMode::Implicit,
	)
	.with_preauth_timeout(SHORT)
	.with_read_timeout(SHORT);
	let (client, stream) = tokio::io::duplex(4096);
	let task = tokio::spawn(async move { server.handle(stream, None).await });
	let guard = AbortOnDrop(task.abort_handle());
	let mut client = timeout(
		IO_DEADLINE,
		connector.connect(
			ServerName::try_from("mail.epistle.test").expect("server name"),
			client,
		),
	)
	.await
	.expect("TLS deadline")
	.expect("TLS handshake");
	assert!(
		line(&mut client)
			.await
			.expect("greeting")
			.expect("open")
			.starts_with("* OK")
	);
	send(
		&mut client,
		format!("L LOGIN tester {PASSWORD}\r\n").as_bytes(),
	)
	.await;
	expect(&mut client, "L OK LOGIN completed\r\n").await;
	(client, data, guard)
}
