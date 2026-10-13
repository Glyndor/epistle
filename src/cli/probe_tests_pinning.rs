//! Pin-verifier tests for the `probe` subcommand.
//!
//! The probe dials the listener on loopback and inspects whatever bytes
//! the server sends. For TLS listeners that means the probe must open
//! a TLS handshake; the verifier it uses decides whether the
//! connection survives that handshake. These tests pin the verifier to
//! the certificate the operator has on disk: a listener that presents
//! a different certificate (because the file was renewed and the
//! listener did not reload) fails the probe with a clear reason; a
//! listener that has nothing pinned at all fails the same way.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::probe_all;
use crate::config::{Config, Listener, ListenerKind, Tls};

/// A pair of self-signed certificates used to distinguish what the
/// server presents from what the operator has on disk. The
/// `tempdir` field keeps the directory alive; the certificate files
/// under it are deleted when `tempdir` is dropped.
struct Pair {
	/// DER of cert A. The server's leaf when the listener is built
	/// from `a_key_pem`.
	a_der: CertificateDer<'static>,
	a_key_pem: String,
	/// The disk path for cert B. The mismatch test pins against this
	/// file while the server still presents A.
	b_path: PathBuf,
	a_path: PathBuf,
	/// Owns the directory under which `a_path` and `b_path` live.
	/// Returned alongside the paths so the caller can keep it alive.
	#[allow(dead_code)]
	tempdir: tempfile::TempDir,
}

impl Pair {
	fn build() -> Self {
		let a = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate A");
		let b = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate B");
		let tempdir = tempfile::tempdir().expect("tempdir");
		let a_path = tempdir.path().join("a.pem");
		let b_path = tempdir.path().join("b.pem");
		std::fs::write(&a_path, a.cert.pem()).expect("write A");
		std::fs::write(&b_path, b.cert.pem()).expect("write B");
		let a_key_pem = a.signing_key.serialize_pem();
		let a_der = a.cert.der().clone();
		Pair {
			a_der,
			a_key_pem,
			a_path,
			b_path,
			tempdir,
		}
	}
}

/// Bring up a TLS listener that hands back `banner` after a successful
/// handshake. Returns the bound port; the accept loop runs until the
/// runtime is dropped.
async fn spawn_tls_server(
	cert_der: CertificateDer<'static>,
	key_pem: String,
	banner: &'static [u8],
) -> u16 {
	crate::tls::ensure_crypto_provider();
	let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
		.await
		.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("server key");
	let server_config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert_der], key)
		.expect("server config");
	let acceptor = TlsAcceptor::from(Arc::new(server_config));
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				if let Ok(mut tls_stream) = acceptor.accept(stream).await {
					let _ = tls_stream.write_all(banner).await;
					let _ = tls_stream.shutdown().await;
				}
			});
		}
	});
	port
}

/// Build a `Config` whose listener set is `listener`, optionally with
/// `cert_file` set so the probe can pin against it. Returns the
/// config plus the tempdir that owns the data dir; the tempdir must
/// outlive the probe run, otherwise the cert file disappears.
fn config_with_tls(
	listener: Listener,
	cert_file: Option<PathBuf>,
	key_file: Option<PathBuf>,
) -> (Config, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let mut config: Config = toml::from_str(&toml).expect("base config");
	config.listeners = vec![listener];
	if let (Some(cert), Some(key)) = (cert_file, key_file) {
		config.tls = Some(Tls {
			cert_file: cert,
			key_file: key,
			client_ca: None,
		});
	}
	(config, dir)
}

fn listener(kind: ListenerKind, port: u16) -> Listener {
	let kind_str = kind.as_str();
	let config_toml = format!("kind = \"{kind_str}\"\naddr = \"127.0.0.1\"\nport = {port}\n");
	toml::from_str(&config_toml).expect("listener parses")
}

const IMAP_GREETING: &[u8] = b"* OK [CAPABILITY IMAP4rev1] mail.example.org ready.\r\n";
const POP3_GREETING: &[u8] = b"+OK mail.example.org ready\r\n";

#[tokio::test]
async fn pin_matches_when_disk_cert_equals_server_cert() {
	let pair = Pair::build();
	let port = spawn_tls_server(pair.a_der.clone(), pair.a_key_pem.clone(), IMAP_GREETING).await;
	let listener = listener(ListenerKind::Imaps, port);
	let (config, _dir) = config_with_tls(
		listener,
		Some(pair.a_path.clone()),
		Some(pair.a_path.clone()),
	);
	let cert_path = config.tls.as_ref().unwrap().cert_file.clone();
	let results = probe_all(&config.listeners, Some(cert_path.as_path()))
		.await
		.expect("probe");
	let line = &results[0];
	assert!(
		line.ok,
		"pinned verifier must accept matching cert: {line:?}"
	);
	assert_eq!(line.kind, "imaps");
}

#[tokio::test]
async fn pin_mismatch_reports_disk_path() {
	// Server presents A; the disk pin points at B. The probe must fail
	// with the path of B in the reason so the operator can see which
	// file did not match the live cert.
	let pair = Pair::build();
	let port = spawn_tls_server(pair.a_der.clone(), pair.a_key_pem.clone(), IMAP_GREETING).await;
	let listener = listener(ListenerKind::Imaps, port);
	let (config, _dir) = config_with_tls(
		listener,
		Some(pair.b_path.clone()),
		Some(pair.b_path.clone()),
	);
	let cert_path = config.tls.as_ref().unwrap().cert_file.clone();
	let results = probe_all(&config.listeners, Some(cert_path.as_path()))
		.await
		.expect("probe");
	let line = &results[0];
	assert!(
		!line.ok,
		"mismatched cert must fail the probe (current verifier accepts any); {line:?}"
	);
	let reason = line.error.as_deref().unwrap_or("");
	assert!(
		reason.contains(pair.b_path.to_str().unwrap_or("")),
		"failure must mention the disk path so the operator sees what did not match; got {reason:?}"
	);
	assert!(
		reason.contains("not reloaded after renewal") || reason.contains("certificate"),
		"failure must explain what kind of mismatch this is; got {reason:?}"
	);
}

#[tokio::test]
async fn tls_listener_without_configured_cert_fails_with_clear_reason() {
	// No `[tls]` block, but a `submissions` listener. The probe must
	// surface a per-listener fail with a reason the operator can act
	// on (configure `[tls] cert_file` to enable the probe), not "the
	// handshake failed against any random cert".
	let pair = Pair::build();
	let port = spawn_tls_server(pair.a_der.clone(), pair.a_key_pem.clone(), POP3_GREETING).await;
	let listener = listener(ListenerKind::Submissions, port);
	let (config, _dir) = config_with_tls(listener, None, None);
	let results = probe_all(&config.listeners, None).await.expect("probe");
	let line = &results[0];
	assert!(
		!line.ok,
		"TLS listener without [tls] must not pretend to succeed; got {line:?}"
	);
	let reason = line.error.as_deref().unwrap_or("");
	assert!(
		reason.contains("no [tls]") || reason.contains("not configured"),
		"reason must explain the missing config; got {reason:?}"
	);
}

#[test]
fn probe_pins_the_acme_certificate_serve_presents() {
	let dir = tempfile::tempdir().expect("dir");
	let pair = rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("pair");
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	std::fs::write(dir.path().join("acme/cert.pem"), pair.cert.pem()).expect("cert");
	std::fs::write(
		dir.path().join("acme/key.pem"),
		pair.signing_key.serialize_pem(),
	)
	.expect("key");
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\n[tls]\ncert_file = '/etc/epistle/bootstrap.pem'\nkey_file = '/etc/epistle/bootstrap.key'\n[acme]\ndirectory_url = 'https://acme.invalid/directory'\ndomains = ['mail.example.org']\n",
		dir.path()
	))
	.expect("config");
	assert_eq!(
		super::pinned_cert_path(&config),
		Some(dir.path().join("acme/cert.pem")),
		"probe must pin the renewed certificate, not the bootstrap one"
	);
}

#[tokio::test]
async fn autoconfigs_listener_is_probed_over_tls() {
	// The HTTPS autodiscovery listener: the probe completes the pinned
	// handshake and then reads an HTTP status line inside it.
	let pair = Pair::build();
	let port = spawn_tls_server(
		pair.a_der.clone(),
		pair.a_key_pem.clone(),
		b"HTTP/1.1 404 Not Found\r\n\r\n",
	)
	.await;
	let listener = listener(ListenerKind::Autoconfigs, port);
	let (config, _dir) = config_with_tls(
		listener,
		Some(pair.a_path.clone()),
		Some(pair.a_path.clone()),
	);
	let cert_path = config.tls.as_ref().unwrap().cert_file.clone();
	let results = probe_all(&config.listeners, Some(cert_path.as_path()))
		.await
		.expect("probe");
	let line = &results[0];
	assert!(line.ok, "HTTPS autoconfig listener must probe ok: {line:?}");
	assert_eq!(line.kind, "autoconfigs");
}
