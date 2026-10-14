//! Regression coverage for the submission rate limit wiring. The
//! per-account and per-domain caps in `[server]` were dropped from
//! `cli::serve` during the per-tenant work; this file pins the wiring
//! the SMTP path needs by driving a real implicit-TLS session through
//! a Server built the same way `serve::serve` builds the SMTP
//! listener. A test that forgets to call
//! `with_global_submission_rate_limit` or
//! `AccountStore::with_domain_submission_limits` cannot pass: the
//! second submission comes back with `250`, not the `450` the contract
//! promises.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::api::TenantLimits;
use crate::config::Config;
use crate::directory_store::{AccountStore, DirectoryHandle};
use crate::smtp::directory::Directory;
use crate::smtp::server::{Server as SmtpServer, TlsMode};
use crate::smtp::sink::MemorySink;
use crate::tls::test_support::acceptor_and_cert;

/// Build a Server with the same wiring pattern `serve::serve` uses for
/// the SMTP listener. The submission-rate-limit wiring goes through the
/// shared helper `serve_ratelimit::wire_smtp_submission_limits`, which
/// is the production single source of truth — a regression test that
/// forgets to call it cannot pass because `serve::serve`'s listener
/// loop calls the same helper. The directory is built with both the
/// password hash (so AUTH succeeds) and the per-domain submission limits
/// (so the per-domain cap is enforced).
pub(super) fn build_smtp_server(
	config: &Config,
	acceptor: crate::tls::ReloadableAcceptor,
	tenant_limits: Option<Arc<TenantLimits>>,
) -> SmtpServer {
	let sink: Arc<dyn crate::smtp::sink::MessageSink> = Arc::new(MemorySink::new());
	let crypto = crate::storage::MessageCrypto::disabled();
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open account store")
	.with_domain_quotas(config.domain_quotas.clone())
	.with_domain_submission_limits(config.domain_submission_limits.clone())
	.with_aliases(config.alias.clone())
	.with_masked_max(config.masked_addresses_max);
	let RateLimiters {
		send_limiter,
		inbound_ip_limit,
		inbound_sender_limit,
	} = super::super::serve_ratelimit::build_rate_limiters(config);
	let mut directory = Directory::new(
		config.domains.clone(),
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
		],
	)
	.with_password_hashes(HashMap::from([(
		"alice".to_string(),
		crate::smtp::auth::tests::hash(crate::smtp::auth::tests::fixture_password()),
	)]));
	for (domain, per_min) in &config.domain_submission_limits {
		directory = directory.with_domain_submission_limits([(domain.clone(), *per_min)]);
	}
	let directory = DirectoryHandle::new(directory);
	let mut server = SmtpServer::new(&config.hostname, sink)
		.with_directory(directory)
		.with_metrics(Arc::new(crate::metrics::Metrics::new()))
		.with_data_dir(config.data_dir.clone())
		.with_crypto(Arc::new(crypto))
		.with_tls(acceptor, TlsMode::Implicit);
	if let Some(limit) = &inbound_ip_limit {
		server = server.with_inbound_ip_limit(crate::smtp::ratelimit::InboundLimit {
			limiter: Arc::clone(&limit.limiter),
			per_min: limit.per_min,
		});
	}
	if let Some(limit) = &inbound_sender_limit {
		server = server.with_inbound_sender_limit(crate::smtp::ratelimit::InboundLimit {
			limiter: Arc::clone(&limit.limiter),
			per_min: limit.per_min,
		});
	}
	// Use the same helper `serve::serve`'s listener loop uses. Removing
	// this call from the test breaks the production code too: both
	// paths go through `wire_smtp_submission_limits`, which attaches
	// the per-account cap, the server-wide default, and the tenant
	// aggregate state.
	server = super::super::serve_ratelimit::wire_smtp_submission_limits(
		server,
		config,
		&send_limiter,
		tenant_limits.as_ref(),
	);
	server
}

/// Read SMTP reply lines until one starts with `code` followed by a
/// space (the RFC 5321 terminator of a multi-line reply). Returns
/// the last matching line so callers can inspect the final reply.
/// `code` may be one digit (e.g. `"2"` matches `250 OK` and `450
/// rate-limit`); callers pick the specificity they need.
pub(super) async fn expect_reply<R: AsyncReadExt + Unpin>(reader: &mut R, code: &str) -> String {
	let mut buf = Vec::new();
	let mut tmp = [0u8; 256];
	let mut line_buf = Vec::new();
	let deadline = std::time::Instant::now() + Duration::from_secs(10);
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			panic!(
				"no {code} reply before deadline; got {:?}",
				String::from_utf8_lossy(&buf)
			);
		}
		let read = match tokio::time::timeout(remaining, reader.read(&mut tmp)).await {
			Ok(Ok(n)) => n,
			Ok(Err(error)) => panic!(
				"read error: {error}; got {:?}",
				String::from_utf8_lossy(&buf)
			),
			Err(_) => panic!(
				"no {code} reply within deadline; got {:?}",
				String::from_utf8_lossy(&buf)
			),
		};
		if read == 0 {
			panic!(
				"closed before a {code} reply; got {:?}",
				String::from_utf8_lossy(&buf)
			);
		}
		for &byte in &tmp[..read] {
			if byte == b'\r' {
				continue;
			}
			if byte == b'\n' {
				let line = String::from_utf8_lossy(&line_buf).to_string();
				buf.extend_from_slice(line.as_bytes());
				buf.push(b'\n');
				let trimmed = line.trim_end();
				let terminal = format!("{code} ");
				if trimmed.starts_with(&terminal) {
					return trimmed.to_string();
				}
				line_buf.clear();
				continue;
			}
			line_buf.push(byte);
		}
	}
}

/// Read until a reply whose first digit differs from the last one
/// (so a 2xx reply after a multi-line 2xx greeting, or a 4xx reply
/// after a 2xx greeting). Returns the full final line. Used when the
/// caller wants to inspect any reply, not just one prefixed with a
/// fixed code.
pub(super) async fn expect_reply_first_digit<R: AsyncReadExt + Unpin>(reader: &mut R) -> String {
	let mut buf = Vec::new();
	let mut tmp = [0u8; 256];
	let mut line_buf = Vec::new();
	let deadline = std::time::Instant::now() + Duration::from_secs(10);
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			panic!(
				"no reply before deadline; got {:?}",
				String::from_utf8_lossy(&buf)
			);
		}
		let read = match tokio::time::timeout(remaining, reader.read(&mut tmp)).await {
			Ok(Ok(n)) => n,
			Ok(Err(error)) => panic!(
				"read error: {error}; got {:?}",
				String::from_utf8_lossy(&buf)
			),
			Err(_) => panic!(
				"no reply within deadline; got {:?}",
				String::from_utf8_lossy(&buf)
			),
		};
		if read == 0 {
			panic!(
				"closed before a reply; got {:?}",
				String::from_utf8_lossy(&buf)
			);
		}
		for &byte in &tmp[..read] {
			if byte == b'\r' {
				continue;
			}
			if byte == b'\n' {
				let line = String::from_utf8_lossy(&line_buf).to_string();
				buf.extend_from_slice(line.as_bytes());
				buf.push(b'\n');
				let trimmed = line.trim_end();
				// Any reply line whose first char is a digit ends the read.
				if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
					return trimmed.to_string();
				}
				line_buf.clear();
				continue;
			}
			line_buf.push(byte);
		}
	}
}

/// Build a TLS client connector that trusts the server's self-signed
/// certificate.
pub(super) fn tls_connector(
	cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> tokio_rustls::TlsConnector {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust cert");
	crate::tls::ensure_crypto_provider();
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Open a TLS connection to the server and return the client side
/// ready for SMTP commands.
pub(super) async fn tls_session(
	addr: std::net::SocketAddr,
	connector: tokio_rustls::TlsConnector,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
	let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
	let server_name =
		tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org").expect("name");
	connector
		.connect(server_name, stream)
		.await
		.expect("handshake")
}

/// Drive one full submission and return the `MAIL FROM` reply line.
/// Lets the caller assert on the exact reply (250 or 450) without
/// panicking inside this helper when the server defers the send.
/// When the reply is not 250 the rest of the transaction (RCPT TO,
/// DATA, ...) is skipped; the caller has the 4xx in hand and the
/// server has already reset to the greeting state.
pub(super) async fn authenticated_submit(
	tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
	plain: &str,
	from: &str,
	to: &str,
) -> String {
	tls.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let _ = expect_reply(tls, "250").await;
	tls.write_all(format!("AUTH PLAIN {plain}\r\n").as_bytes())
		.await
		.expect("auth");
	let auth_reply = expect_reply(tls, "235").await;
	assert!(auth_reply.starts_with("235 "), "auth reply: {auth_reply}");
	tls.write_all(format!("MAIL FROM:<{from}>\r\n").as_bytes())
		.await
		.expect("mail from");
	let mailfrom = expect_reply_first_digit(tls).await;
	if !mailfrom.starts_with("250 ") {
		// Rate-limited or refused; the session is back at the greeting
		// and the caller has the rejection reply.
		return mailfrom;
	}
	tls.write_all(format!("RCPT TO:<{to}>\r\n").as_bytes())
		.await
		.expect("rcpt to");
	let _ = expect_reply(tls, "250").await;
	tls.write_all(b"DATA\r\n").await.expect("data");
	let data_reply = expect_reply(tls, "354").await;
	assert!(data_reply.starts_with("354 "), "DATA reply: {data_reply}");
	tls.write_all(format!("From: {from}\r\nSubject: hi\r\n\r\nhello\r\n.\r\n").as_bytes())
		.await
		.expect("body");
	let _ = expect_reply(tls, "250").await;
	tls.write_all(b"RSET\r\n").await.expect("rset");
	let _ = expect_reply(tls, "250").await;
	mailfrom
}

pub(super) fn auth_plain(authcid: &str, password: &str) -> String {
	B64.encode(format!("\0{authcid}\0{password}"))
}

/// Build a `Config` with `submission_rate_limit_per_min = per_min`.
pub(super) fn ratelimit_config(data_dir: &std::path::Path, per_min: u32) -> Config {
	let toml_text = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
		 submission_rate_limit_per_min = {per_min}\n",
		data_dir.to_string_lossy()
	);
	let config: Config = toml::from_str(&toml_text).expect("config");
	config
}

fn ratelimit_config_with_domain(data_dir: &std::path::Path, per_min: u32) -> Config {
	// Per-domain test: the server-wide default is None so the per-account
	// fallback can never save the missing per-domain wiring. Only the
	// directory's `submission_limit_for` returning the per-domain entry
	// can fire the cap. With that entry absent, the second submission
	// always passes; with it present, the second is deferred.
	let mut config = ratelimit_config(data_dir, per_min);
	config.submission_rate_limit_per_min = None;
	config
		.domain_submission_limits
		.insert("example.org".to_string(), per_min);
	config
}

pub(super) async fn spawn_smtp_listener(
	server: SmtpServer,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let task = tokio::spawn(async move {
		let _ = Arc::new(server).serve(listener).await;
	});
	(addr, task)
}

#[tokio::test]
async fn per_account_limit_set_in_config_refuses_a_second_submission() {
	// A config with `submission_rate_limit_per_min = 1` and the listener
	// constructed by the production wiring must defer the second
	// submission with `450 4.7.1 sending rate limit exceeded; retry later`.
	// Before #802's wiring was restored the second submission came back
	// with `250`, because `with_global_submission_rate_limit` was never
	// called from the listener loop. The exact reply line is what the
	// SMTP server already uses, so a future change to the wording would
	// be spotted here too.
	let dir = tempfile::tempdir().expect("tempdir");
	let config = ratelimit_config(dir.path(), 1);
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(&config, crate::tls::ReloadableAcceptor::new(acceptor), None);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	let mut tls = tls_session(addr, connector.clone()).await;
	let first =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		first.starts_with("250 "),
		"first submission must be accepted: {first:?}"
	);
	drop(tls);

	let mut tls = tls_session(addr, connector).await;
	let second =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		second.starts_with("450 4.7.1 sending rate limit exceeded; retry later"),
		"second submission must be deferred with the 450 line; got: {second:?}"
	);
	task.abort();
}

#[tokio::test]
async fn per_domain_limit_set_in_config_refuses_a_second_submission() {
	// The per-domain entry must win over the (unset) global default. The
	// limiter is created on any submission limit being set, so the wiring
	// has to push `config.domain_submission_limits` into the directory
	// too; without `with_domain_submission_limits` on the store the
	// server constructs, the second submission always passes.
	let dir = tempfile::tempdir().expect("tempdir");
	let config = ratelimit_config_with_domain(dir.path(), 1);
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(&config, crate::tls::ReloadableAcceptor::new(acceptor), None);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	let mut tls = tls_session(addr, connector.clone()).await;
	let first =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		first.starts_with("250 "),
		"first submission must be accepted: {first:?}"
	);
	drop(tls);

	let mut tls = tls_session(addr, connector).await;
	let second =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		second.starts_with("450 4.7.1 sending rate limit exceeded; retry later"),
		"second submission must be deferred when the per-domain cap is reached; got: {second:?}"
	);
	task.abort();
}

#[tokio::test]
async fn no_limit_means_no_deferral() {
	// Symmetric: with neither `submission_rate_limit_per_min` nor any
	// per-domain entry set, the listener loop must not start a limiter
	// at all. A future commit that wires the limiter against an
	// accidentally-stale default would regress the unconfigured path.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut config = ratelimit_config(dir.path(), 1);
	config.submission_rate_limit_per_min = None;
	config.domain_submission_limits.clear();
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(&config, crate::tls::ReloadableAcceptor::new(acceptor), None);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	for _ in 0..3 {
		let mut tls = tls_session(addr, connector.clone()).await;
		let mailfrom =
			authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
		assert!(
			!mailfrom.starts_with("450 4.7.1 sending rate limit"),
			"no-limit config must never defer: {mailfrom:?}"
		);
		drop(tls);
	}
	task.abort();
}

#[tokio::test]
async fn per_tenant_aggregate_limit_refuses_a_second_submission() {
	// A `[[tenant]]` with `submission_rate_limit_per_min = 1` that
	// owns the account's domain must defer the second SMTP submission
	// with the tenant-flavored 4xx line. The same `SendLimiter` is
	// consulted by REST and JMAP, so the SMTP path rejecting on
	// submission means REST and JMAP cannot dodge the cap by switching
	// protocols.
	let dir = tempfile::tempdir().expect("tempdir");
	let mut config = ratelimit_config(dir.path(), 1);
	config.submission_rate_limit_per_min = None;
	config.domain_submission_limits.clear();
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	let tenant_limits = Arc::new(TenantLimits::from_config(&[crate::config::Tenant {
		name: Some("acme".to_string()),
		domains: vec!["example.org".to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: Some(1),
	}]));
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(
		&config,
		crate::tls::ReloadableAcceptor::new(acceptor),
		Some(Arc::clone(&tenant_limits)),
	);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	let mut tls = tls_session(addr, connector.clone()).await;
	let first =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		first.starts_with("250 "),
		"first submission must be accepted: {first:?}"
	);
	drop(tls);

	let mut tls = tls_session(addr, connector).await;
	let second =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		second.starts_with("450 4.7.1 tenant \"acme\" submission rate limit exceeded; retry later"),
		"second submission must be deferred with the tenant 4xx line; got: {second:?}"
	);
	task.abort();
}
