//! The two HTTPS listeners with their own accept loops (MTA-STS policy
//! and autoconfig over TLS) keep accepting after failed accepts too.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_rustls::rustls::pki_types::CertificateDer;

use super::scripted::failing_then_connecting;

const ERRORS: [i32; 3] = [libc::EMFILE, libc::ECONNABORTED, libc::ENOBUFS];
const PATIENCE: Duration = Duration::from_secs(30);

/// TLS to `name` over `client`, GET `path`; the status line, or `None`
/// when the listener never answered.
async fn get(
	client: DuplexStream,
	cert: CertificateDer<'static>,
	name: &'static str,
	path: &str,
) -> Option<String> {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	let exchange = async {
		let mut tls = connector
			.connect(name.try_into().expect("name"), client)
			.await
			.ok()?;
		tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes())
			.await
			.ok()?;
		let mut response = [0u8; 512];
		let n = tls.read(&mut response).await.ok()?;
		String::from_utf8_lossy(&response[..n])
			.lines()
			.next()
			.map(str::to_string)
	};
	tokio::time::timeout(PATIENCE, exchange)
		.await
		.ok()
		.flatten()
}

#[tokio::test(start_paused = true)]
async fn mta_sts_keeps_accepting() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir(dir.path().join("policy")).expect("policy dir");
	std::fs::write(
		dir.path().join("policy/mta-sts.txt"),
		"version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 604800\n",
	)
	.expect("policy");
	let certified =
		rcgen::generate_simple_self_signed(vec!["mta-sts.example.org".into()]).expect("cert");
	let tls = crate::config::Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	std::fs::write(&tls.cert_file, certified.cert.pem()).expect("cert");
	std::fs::write(&tls.key_file, certified.signing_key.serialize_pem()).expect("key");
	let server =
		crate::mtasts::server::Server::new(dir.path().join("policy"), tls).expect("server");
	let (listener, client) = failing_then_connecting(&ERRORS);
	tokio::spawn(server.serve_on(listener, Arc::new(crate::metrics::Metrics::new())));
	let status = get(
		client,
		certified.cert.der().clone(),
		"mta-sts.example.org",
		"/.well-known/mta-sts.txt",
	)
	.await;
	assert_eq!(
		status.as_deref(),
		Some("HTTP/1.1 200 OK"),
		"MTA-STS: the listener stopped after a failed accept"
	);
}

#[tokio::test(start_paused = true)]
async fn autoconfig_over_tls_keeps_accepting() {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let router = axum::Router::new().route("/", axum::routing::get(|| async { "up" }));
	let (listener, client) = failing_then_connecting(&ERRORS);
	tokio::spawn(crate::autodiscovery::serve_on(
		listener,
		router,
		Some(acceptor),
		8,
	));
	let status = get(client, cert, "mail.example.org", "/").await;
	assert_eq!(
		status.as_deref(),
		Some("HTTP/1.1 200 OK"),
		"autoconfig: the listener stopped after a failed accept"
	);
}
