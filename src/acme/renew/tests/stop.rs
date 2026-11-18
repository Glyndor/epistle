//! Stopping the renewal loop withdraws the dns-01 records still published
//! before it returns, and a start withdraws what an earlier run left.

use super::*;
use crate::acme::challenge::fake_zone::{FakeZone, dns01};
use crate::acme::challenge::{Dns01, journal_path};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Notify;

const DOMAIN: &str = "mail.example.org";
const TOKEN: &str = "token-aaaa";

/// A dns-01 responder that says when its first `withdraw_pending`, the one
/// the loop runs at start, has returned.
struct Started {
	inner: Dns01,
	started: Notify,
}

impl ChallengeResponder for Started {
	fn kind(&self) -> &'static str {
		self.inner.kind()
	}

	fn publish<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + 'a>> {
		self.inner.publish(domain, token, key)
	}

	fn withdraw<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
		self.inner.withdraw(domain, token, key)
	}

	fn withdraw_pending(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
		Box::pin(async {
			self.inner.withdraw_pending().await;
			self.started.notify_one();
		})
	}
}

/// A data directory holding a certificate far from its renewal window, so
/// the loop has nothing to order and sleeps.
fn data_dir() -> (tempfile::TempDir, ReloadableAcceptor) {
	let dir = tempfile::tempdir().expect("directory");
	let (cert, key) = issued_certificate(2099, 1, 1);
	let (cert, key) = (cert.pem(), key.serialize_pem());
	fs::create_dir_all(dir.path().join("acme")).expect("ACME directory");
	fs::write(cert_path(dir.path()), &cert).expect("certificate file");
	fs::write(key_path(dir.path()), &key).expect("key file");
	let acceptor =
		crate::tls::acceptor_from_pem(cert.as_bytes(), key.as_bytes()).expect("acceptor");
	(dir, ReloadableAcceptor::new(acceptor))
}

fn spawn(
	responder: Arc<dyn ChallengeResponder>,
	dir: &Path,
	reloadable: ReloadableAcceptor,
) -> Renewal {
	let dir = dir.to_path_buf();
	Renewal::spawn(|stop| {
		run(
			RenewalJob {
				directory_url: "https://acme.invalid/directory".into(),
				contacts: Vec::new(),
				domains: vec![DOMAIN.into()],
				responder,
				account_key: account_key_path(&dir),
				data_dir: dir,
				reloadable: Some(reloadable),
				renew_before_days: 30,
				tlsa: None,
				dns: None,
			},
			stop,
		)
	})
}

/// Wait for the loop's start withdrawal, failing after five seconds rather
/// than hanging when it never runs.
async fn started(responder: &Started) {
	tokio::time::timeout(Duration::from_secs(5), responder.started.notified())
		.await
		.expect("the loop withdrew what was pending when it started");
}

fn key() -> AccountKey {
	AccountKey::generate().expect("key").0
}

#[tokio::test]
async fn stopping_the_loop_withdraws_what_is_still_published_before_it_returns() {
	let (dir, reloadable) = data_dir();
	let provider = FakeZone::new(&["example.org"]);
	let responder = Arc::new(Started {
		inner: dns01(&provider).with_journal(journal_path(dir.path())),
		started: Notify::new(),
	});
	let renewal = spawn(responder.clone(), dir.path(), reloadable);
	started(&responder).await;
	// An order in flight has published its record when the stop comes.
	responder
		.publish(DOMAIN, TOKEN, &key())
		.await
		.expect("publish");

	assert!(
		renewal.stop(Duration::from_secs(10)).await,
		"stopped in time"
	);

	assert_eq!(provider.deletes().len(), 1, "calls: {:?}", provider.calls());
	assert!(
		!journal_path(dir.path()).exists(),
		"nothing is left for the next start"
	);
}

#[tokio::test]
async fn a_stop_with_nothing_published_returns_at_once_and_touches_nothing() {
	let (dir, reloadable) = data_dir();
	let provider = FakeZone::new(&["example.org"]);
	let responder = Arc::new(Started {
		inner: dns01(&provider).with_journal(journal_path(dir.path())),
		started: Notify::new(),
	});
	let renewal = spawn(responder.clone(), dir.path(), reloadable);
	started(&responder).await;

	let began = std::time::Instant::now();
	assert!(renewal.stop(Duration::from_secs(60)).await);
	assert!(
		began.elapsed() < Duration::from_secs(5),
		"took {:?}",
		began.elapsed()
	);
	assert!(provider.calls().is_empty(), "calls: {:?}", provider.calls());
}

#[tokio::test]
async fn a_withdrawal_past_the_deadline_is_left_to_the_next_start() {
	let (dir, reloadable) = data_dir();
	let provider = FakeZone::new(&["example.org"]);
	let responder = Arc::new(Started {
		inner: dns01(&provider).with_journal(journal_path(dir.path())),
		started: Notify::new(),
	});
	let renewal = spawn(responder.clone(), dir.path(), reloadable);
	started(&responder).await;
	responder
		.publish(DOMAIN, TOKEN, &key())
		.await
		.expect("publish");
	provider.delete_stalls.store(true, Ordering::Relaxed);

	assert!(
		!renewal.stop(Duration::from_millis(200)).await,
		"the delete stalled"
	);
	assert!(
		journal_path(dir.path()).exists(),
		"the record is still pending"
	);

	// The next start takes the record over from the journal and removes it.
	let next = FakeZone::new(&["example.org"]);
	let (_, reloadable) = data_dir();
	let restarted = spawn(
		Arc::new(dns01(&next).with_journal(journal_path(dir.path()))),
		dir.path(),
		reloadable,
	);
	assert_eq!(
		next.wait_for_deletes(1).await.len(),
		1,
		"calls: {:?}",
		next.calls()
	);
	assert!(restarted.stop(Duration::from_secs(10)).await);
	assert!(!journal_path(dir.path()).exists());
}

#[tokio::test]
async fn the_loop_withdraws_what_an_earlier_run_left_before_it_is_stopped() {
	let (dir, reloadable) = data_dir();
	let first = FakeZone::new(&["example.org"]);
	dns01(&first)
		.with_journal(journal_path(dir.path()))
		.publish(DOMAIN, TOKEN, &key())
		.await
		.expect("publish");

	let provider = FakeZone::new(&["example.org"]);
	let renewal = spawn(
		Arc::new(dns01(&provider).with_journal(journal_path(dir.path()))),
		dir.path(),
		reloadable,
	);
	// Waited for while the loop runs, so the withdrawal at stop cannot be
	// the one that removed it.
	let deletes = provider.wait_for_deletes(1).await;
	assert_eq!(deletes.len(), 1, "calls: {:?}", provider.calls());
	assert!(renewal.stop(Duration::from_secs(10)).await);
	assert_eq!(provider.deletes().len(), 1, "removed once");
}

/// Every pass of the loop builds the DNS provider again before it does
/// anything with it, so a credential that changed is picked up without a
/// restart.
#[tokio::test]
async fn every_pass_of_the_loop_builds_the_provider_again() {
	use crate::dns::provider::DnsProvider;
	use crate::dns::provider::live::LiveProvider;
	let (dir, reloadable) = data_dir();
	let provider = FakeZone::new(&["example.org"]);
	let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let source = {
		let (builds, provider) = (Arc::clone(&builds), Arc::clone(&provider));
		Arc::new(move || {
			builds.fetch_add(1, Ordering::SeqCst);
			Ok(Arc::clone(&provider) as Arc<dyn DnsProvider>)
		})
	};
	let live = Arc::new(LiveProvider::from_source(
		Arc::clone(&provider) as Arc<dyn DnsProvider>,
		source,
	));
	let path = dir.path().to_path_buf();
	let renewal = Renewal::spawn(|stop| {
		run(
			RenewalJob {
				directory_url: "https://acme.invalid/directory".into(),
				contacts: Vec::new(),
				domains: vec![DOMAIN.into()],
				responder: Arc::new(dns01(&provider)),
				account_key: account_key_path(&path),
				data_dir: path,
				reloadable: Some(reloadable),
				renew_before_days: 30,
				tlsa: None,
				dns: Some(live),
			},
			stop,
		)
	});
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while builds.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert_eq!(builds.load(Ordering::SeqCst), 1, "the first pass built it");
	assert!(renewal.stop(Duration::from_secs(10)).await);
}
