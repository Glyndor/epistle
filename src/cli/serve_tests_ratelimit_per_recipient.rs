//! Per-recipient submission rate limit coverage.
//!
//! The per-account, per-domain and per-tenant caps all charge one unit per
//! recipient, not one per message. The two tests in this file seed a
//! recipient count high enough to exhaust the cap on the first submission
//! and assert that the next single-recipient submission is deferred. They
//! share `authenticated_submit_two_recipients` so a single two-recipient
//! transaction can be replayed against any of the three caps without
//! duplicating the SMTP driver.
//!
//! Lives in a separate file from `serve_tests_ratelimit.rs` because the
//! line-count budget would otherwise cap the existing suite. The SMTP-side
//! helpers are made `pub(super)` on the sibling module and reused here.

use std::sync::Arc;

use crate::api::TenantLimits;
use crate::tls::test_support::acceptor_and_cert;

use super::tests_ratelimit::{
	authenticated_submit, auth_plain, build_smtp_server, expect_reply, expect_reply_first_digit,
	ratelimit_config, spawn_smtp_listener, tls_connector, tls_session,
};

#[tokio::test]
async fn per_tenant_limit_charges_per_recipient() {
	// A single submission with two recipients costs two units against
	// the tenant aggregate budget. With `submission_rate_limit_per_min
	// = 2` the first submission fits and the second is deferred.
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
		submission_rate_limit_per_min: Some(2),
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
	let first = authenticated_submit_two_recipients(
		&mut tls,
		&plain,
		"alice@example.org",
		&["bob@example.org", "carol@example.org"],
	)
	.await;
	assert!(
		first.starts_with("250 "),
		"first two-recipient submission must be accepted: {first:?}"
	);
	drop(tls);

	let mut tls = tls_session(addr, connector).await;
	let second =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		second.starts_with("450 4.7.1 tenant \"acme\" submission rate limit exceeded; retry later"),
		"second submission must be deferred when the per-tenant budget is exhausted; got: {second:?}"
	);
	task.abort();
}

#[tokio::test]
async fn per_account_limit_charges_per_recipient() {
	// A two-recipient submission must cost two units against the
	// per-account submission budget, the same as the tenant aggregate
	// budget charges per recipient. With `submission_rate_limit_per_min
	// = 2` the first two-recipient submission fits and the second
	// single-recipient submission is deferred. Before per-recipient
	// counting reached the per-account path the second submission came
	// back with `250` because both messages cost only one unit each.
	let dir = tempfile::tempdir().expect("tempdir");
	let config = ratelimit_config(dir.path(), 2);
	let plain = auth_plain("alice", crate::smtp::auth::tests::fixture_password());
	let (acceptor, cert) = acceptor_and_cert();
	let server = build_smtp_server(&config, crate::tls::ReloadableAcceptor::new(acceptor), None);
	let (addr, task) = spawn_smtp_listener(server).await;
	let connector = tls_connector(cert);

	let mut tls = tls_session(addr, connector.clone()).await;
	let first = authenticated_submit_two_recipients(
		&mut tls,
		&plain,
		"alice@example.org",
		&["bob@example.org", "carol@example.org"],
	)
	.await;
	assert!(
		first.starts_with("250 "),
		"first two-recipient submission must be accepted: {first:?}"
	);
	drop(tls);

	let mut tls = tls_session(addr, connector).await;
	let second =
		authenticated_submit(&mut tls, &plain, "alice@example.org", "bob@example.org").await;
	assert!(
		second.starts_with("450 4.7.1 sending rate limit exceeded; retry later"),
		"second submission must be deferred when the per-account budget is exhausted; got: {second:?}"
	);
	task.abort();
}

/// Drive a two-recipient submission and return the MAIL FROM reply.
/// Mirrors `authenticated_submit` but with two RCPT TO commands so the
/// tenant aggregate budget charges two units.
pub(super) async fn authenticated_submit_two_recipients(
	tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
	plain: &str,
	from: &str,
	to: &[&str],
) -> String {
	use tokio::io::AsyncWriteExt;
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
		return mailfrom;
	}
	for recipient in to {
		tls.write_all(format!("RCPT TO:<{recipient}>\r\n").as_bytes())
			.await
			.expect("rcpt to");
		let _ = expect_reply(tls, "250").await;
	}
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