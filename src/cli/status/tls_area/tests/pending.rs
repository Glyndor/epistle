//! `status` shows a TLSA publication a DNS failure left pending.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::evaluate;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const NOW: u64 = 1_791_504_000;

fn tls_ctx(dir: &Path) -> crate::cli::status::Ctx {
	let key = rcgen::KeyPair::generate().expect("key");
	let params =
		rcgen::CertificateParams::new(vec!["mail.example.org".to_string()]).expect("params");
	let cert = params.self_signed(&key).expect("certificate");
	let (cert_path, key_path) = (dir.join("tls.pem"), dir.join("tls.key"));
	std::fs::write(&cert_path, cert.pem()).expect("write cert");
	std::fs::write(&key_path, key.serialize_pem()).expect("write key");
	let mut ctx = ctx(
		dir,
		&format!(
			"[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
			cert_path.display().to_string(),
			key_path.display().to_string()
		),
	);
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	ctx
}

#[tokio::test]
async fn a_pending_publication_is_shown_with_its_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path());
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let mut state = crate::dns::tlsa::State::load(&data_dir, "mail.example.org");
	state.fail(
		"3 0 1 abcd",
		"the provider is down".to_string(),
		NOW - 7_300,
	);
	state.save(&data_dir).expect("state");

	let report = evaluate(&ctx, &FakeDns::default()).await;

	let found = report
		.items
		.iter()
		.find(|item| item.name == "tlsa-pending")
		.expect("the owed publication is an item");
	assert_eq!(found.status, Level::Warn);
	assert!(found.detail.contains("2 h"), "{}", found.detail);
	assert!(found.detail.contains("the provider is down"));
	assert!(found.detail.contains("3 0 1 abcd"));
}

#[tokio::test]
async fn nothing_owed_shows_no_item() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path());
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert!(report.items.iter().all(|item| item.name != "tlsa-pending"));
}
