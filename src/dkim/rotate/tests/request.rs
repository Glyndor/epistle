//! Operator-requested rotation: the server performs it, the signer switches.

use super::*;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dns::provider::ProviderError;

const DAY: u64 = 86_400;

#[derive(Default)]
struct Dns {
	upserts: Mutex<Vec<String>>,
	deletes: Mutex<Vec<String>>,
	fail: AtomicBool,
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for Dns {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			if self.fail.load(Ordering::SeqCst) {
				return Err(ProviderError::Remote("rate limited".into()));
			}
			self.upserts.lock().unwrap().push(record.name);
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.deletes.lock().unwrap().push(record.name);
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

struct Fixture {
	dir: tempfile::TempDir,
	dns: Arc<Dns>,
	signer: ReloadableSigner,
	rotator: Rotator,
}

/// Active selector `ed0` rotated on day 0, optionally with a previous `ed-old`.
fn fixture(with_previous: bool) -> Fixture {
	let dir = tempfile::tempdir().expect("dir");
	let data = dir.path();
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let active = data.join("dkim-ed0.key");
	std::fs::write(&active, &pem).expect("active key");
	let previous = with_previous.then(|| {
		let old = data.join("dkim-ed-old.key");
		std::fs::write(&old, &pem).expect("old key");
		Previous {
			selector: "ed-old".into(),
			key_file: old,
			retire_at: 99 * DAY,
			rsa: None,
		}
	});
	let state = RotationState {
		selector: "ed0".into(),
		key_file: active.clone(),
		rotated_at: 0,
		previous,
		pending: None,
		rsa: None,
	};
	std::fs::write(data.join(STATE_FILE), serde_json::to_vec(&state).unwrap()).expect("state");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("ed0", &active).expect("signer")));
	let dns = Arc::new(Dns::default());
	let rotator = Rotator::new(
		data.to_path_buf(),
		signer.clone(),
		dns.clone(),
		"example.org".into(),
		vec!["example.org".into(), "mail.example.org".into()],
		90 * DAY,
		14 * DAY,
	);
	Fixture {
		dir,
		dns,
		signer,
		rotator,
	}
}

fn saved(data: &std::path::Path) -> RotationState {
	read_state(data).expect("state").expect("present")
}

#[tokio::test]
async fn cycle_serves_a_request_and_the_signer_switches() {
	let f = fixture(false);
	request_rotation(f.dir.path(), 5 * DAY).expect("request");
	assert_eq!(f.signer.current().selector(), "ed0");

	f.rotator.cycle(5 * DAY + 60, false).await.expect("cycle");

	assert_eq!(
		f.signer.current().selector(),
		"ed5",
		"signer must switch to the new key"
	);
	let state = saved(f.dir.path());
	assert_eq!(state.selector, "ed5");
	assert_eq!(state.previous.expect("previous").selector, "ed0");
	let mut upserts = f.dns.upserts.lock().unwrap().clone();
	upserts.sort();
	assert_eq!(
		upserts,
		vec![
			"ed5._domainkey.example.org",
			"ed5._domainkey.mail.example.org"
		],
		"TXT must be published for every signing domain"
	);
	assert!(
		pending_request(f.dir.path()).is_none(),
		"request must be consumed"
	);
}

#[tokio::test]
async fn without_a_request_and_no_schedule_due_nothing_rotates() {
	let f = fixture(false);
	f.rotator.cycle(5 * DAY, false).await.expect("cycle");
	assert_eq!(f.signer.current().selector(), "ed0");
	assert!(f.dns.upserts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_publication_keeps_the_request_and_retries_after_the_delay() {
	let f = fixture(false);
	request_rotation(f.dir.path(), 5 * DAY).expect("request");
	f.dns.fail.store(true, Ordering::SeqCst);

	f.rotator
		.cycle(5 * DAY + 60, false)
		.await
		.expect("cycle logs the failure");
	assert_eq!(
		f.signer.current().selector(),
		"ed0",
		"failed rotation must not switch the signer"
	);
	assert_eq!(saved(f.dir.path()).selector, "ed0");
	assert!(
		pending_request(f.dir.path()).is_some(),
		"request must survive the failure"
	);
	let error = last_error(f.dir.path()).expect("error recorded");
	assert!(error.contains("rate limited"), "recorded error: {error}");

	// Provider recovers, but the retry delay has not elapsed.
	f.dns.fail.store(false, Ordering::SeqCst);
	f.rotator.cycle(5 * DAY + 120, false).await.expect("cycle");
	assert_eq!(
		f.signer.current().selector(),
		"ed0",
		"retry must wait for the delay"
	);

	f.rotator.cycle(5 * DAY + 700, false).await.expect("cycle");
	assert_eq!(f.signer.current().selector(), "ed5");
	assert!(pending_request(f.dir.path()).is_none());
	assert!(
		last_error(f.dir.path()).is_none(),
		"success clears the recorded error"
	);
}

#[tokio::test]
async fn forced_rotation_retires_an_older_previous_selector_first() {
	let f = fixture(true);
	request_rotation(f.dir.path(), 5 * DAY).expect("request");

	f.rotator.cycle(5 * DAY + 60, false).await.expect("cycle");

	let deletes = f.dns.deletes.lock().unwrap().clone();
	assert!(
		deletes.contains(&"ed-old._domainkey.example.org".to_string())
			&& deletes.contains(&"ed-old._domainkey.mail.example.org".to_string()),
		"the older previous TXT must be withdrawn from every domain: {deletes:?}"
	);
	assert!(
		!f.dir.path().join("dkim-ed-old.key").exists(),
		"its key file must be removed"
	);
	let state = saved(f.dir.path());
	assert_eq!(state.selector, "ed5");
	assert_eq!(state.previous.expect("previous").selector, "ed0");
}

#[tokio::test]
async fn second_rotation_on_the_same_day_is_refused_and_leaves_state_alone() {
	let f = fixture(false);
	f.rotator.force_rotate(5 * DAY).await.expect("first");
	let before = saved(f.dir.path());

	let error = f
		.rotator
		.force_rotate(5 * DAY + 3600)
		.await
		.expect_err("same day");

	assert!(
		error.to_string().contains("ed5 is already active"),
		"{error}"
	);
	assert_eq!(saved(f.dir.path()), before);
}

#[tokio::test]
async fn invalid_state_file_stops_the_cycle_instead_of_bootstrapping_a_second_key() {
	let f = fixture(false);
	std::fs::write(f.dir.path().join(STATE_FILE), "not json").expect("corrupt");
	let error = f.rotator.tick(200 * DAY).await.expect_err("must fail");
	assert!(error.to_string().contains(STATE_FILE), "{error}");
	assert!(
		f.dns.upserts.lock().unwrap().is_empty(),
		"nothing may be published"
	);
}

#[test]
fn asking_twice_keeps_the_first_request() {
	let dir = tempfile::tempdir().expect("dir");
	request_rotation(dir.path(), 10).expect("first");
	request_rotation(dir.path(), 99).expect("second");
	assert_eq!(
		pending_request(dir.path()),
		Some(RotationRequest { requested_at: 10 })
	);
}

#[allow(unused_imports)]
use super::super::rsa;
