//! Operator-requested renewal: the server serves it through the issue path.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::acme::renew_request::{
	Backoff, Issuer, Outcome, cycle, last_error, pending_request, request_renewal,
};

const NOW: u64 = 1_893_456_000; // 2030-01-01 UTC.

#[derive(Default)]
struct Recorder {
	calls: AtomicUsize,
	fail: AtomicBool,
}

impl Issuer for Recorder {
	fn issue(&self) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + '_>> {
		Box::pin(async move {
			self.calls.fetch_add(1, Ordering::SeqCst);
			if self.fail.load(Ordering::SeqCst) {
				Err(AcmeError::Transport("CA unreachable".into()))
			} else {
				Ok(())
			}
		})
	}
}

/// A certificate valid for another 300 days, so no renewal is due.
fn fresh_certificate(dir: &Path) {
	let cert = issued_certificate(2030, 10, 28);
	fs::create_dir_all(dir.join("acme")).expect("acme dir");
	fs::write(cert_path(dir), cert.pem()).expect("write");
}

#[tokio::test]
async fn forced_request_issues_even_when_the_certificate_is_not_due() {
	let dir = tempfile::tempdir().expect("dir");
	fresh_certificate(dir.path());
	let issuer = Recorder::default();
	let mut backoff = Backoff::default();
	assert_eq!(
		cycle(&issuer, dir.path(), 30, NOW, &mut backoff).await,
		Outcome::Idle
	);
	assert_eq!(issuer.calls.load(Ordering::SeqCst), 0, "nothing is due");

	request_renewal(dir.path(), true, NOW).expect("request");
	assert_eq!(
		cycle(&issuer, dir.path(), 30, NOW, &mut backoff).await,
		Outcome::Issued
	);
	assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
	assert!(
		pending_request(dir.path()).is_none(),
		"request must be consumed"
	);
}

#[tokio::test]
async fn unforced_request_is_dropped_while_the_certificate_is_not_due() {
	let dir = tempfile::tempdir().expect("dir");
	fresh_certificate(dir.path());
	let issuer = Recorder::default();
	request_renewal(dir.path(), false, NOW).expect("request");
	let outcome = cycle(&issuer, dir.path(), 30, NOW, &mut Backoff::default()).await;
	assert_eq!(outcome, Outcome::NotDue);
	assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
	assert!(pending_request(dir.path()).is_none());
}

#[tokio::test]
async fn unforced_request_issues_inside_the_renewal_window() {
	let dir = tempfile::tempdir().expect("dir");
	fresh_certificate(dir.path());
	let issuer = Recorder::default();
	request_renewal(dir.path(), false, NOW).expect("request");
	// 280 days later only 20 days remain, inside a 30 day window.
	let later = NOW + 280 * 86_400;
	let outcome = cycle(&issuer, dir.path(), 30, later, &mut Backoff::default()).await;
	assert_eq!(outcome, Outcome::Issued);
	assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_issuance_keeps_the_request_and_waits_before_retrying() {
	let dir = tempfile::tempdir().expect("dir");
	fresh_certificate(dir.path());
	let issuer = Recorder::default();
	issuer.fail.store(true, Ordering::SeqCst);
	let mut backoff = Backoff::default();
	request_renewal(dir.path(), true, NOW).expect("request");

	let outcome = cycle(&issuer, dir.path(), 30, NOW, &mut backoff).await;
	assert_eq!(
		outcome,
		Outcome::Failed("transport error: CA unreachable".into())
	);
	assert!(
		pending_request(dir.path()).is_some(),
		"request must survive the failure"
	);
	assert!(
		last_error(dir.path())
			.expect("error")
			.contains("CA unreachable")
	);

	issuer.fail.store(false, Ordering::SeqCst);
	assert_eq!(
		cycle(&issuer, dir.path(), 30, NOW + 60, &mut backoff).await,
		Outcome::Idle
	);
	assert_eq!(
		issuer.calls.load(Ordering::SeqCst),
		1,
		"retry must wait out the back-off"
	);

	let outcome = cycle(&issuer, dir.path(), 30, NOW + 3601, &mut backoff).await;
	assert_eq!(outcome, Outcome::Issued);
	assert!(pending_request(dir.path()).is_none());
	assert!(
		last_error(dir.path()).is_none(),
		"success clears the recorded error"
	);
}

#[tokio::test]
async fn scheduled_renewal_still_runs_without_a_request() {
	let dir = tempfile::tempdir().expect("dir");
	let issuer = Recorder::default();
	let outcome = cycle(&issuer, dir.path(), 30, NOW, &mut Backoff::default()).await;
	assert_eq!(
		outcome,
		Outcome::Issued,
		"no certificate on disk means renewal is due"
	);
	assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_second_request_keeps_the_first_time_and_any_force() {
	let dir = tempfile::tempdir().expect("dir");
	request_renewal(dir.path(), true, 10).expect("first");
	request_renewal(dir.path(), false, 99).expect("second");
	let request = pending_request(dir.path()).expect("pending");
	assert_eq!((request.force, request.requested_at), (true, 10));
}
