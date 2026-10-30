use std::sync::Arc;

use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::{sha256, to_hex};
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::settings::Authority;

const DAY: i64 = 20_740;

fn sealed_day() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	crate::evidence::checkpoint::seal_closed_days(dir.path(), &key, true, at(DAY + 1, 0))
		.expect("seal");
	dir
}

fn settings(url: String, tsa: &FakeTsa) -> Settings {
	Settings {
		enabled: true,
		authorities: vec![Authority {
			url,
			anchors: vec![to_hex(&tsa.anchor)],
			policy: None,
			local_test: true,
			token_file: None,
		}],
	}
}

#[tokio::test]
async fn a_sealed_day_gets_a_token_over_its_checkpoint_hash() {
	let dir = sealed_day();
	let tsa = Arc::new(FakeTsa::new(at(DAY + 1, 0)));
	let url = Arc::clone(&tsa).serve().await;
	let pass = stamp_due(dir.path(), &settings(url, &tsa), at(DAY + 1, 0))
		.await
		.expect("pass");
	assert_eq!(pass.stamped, vec![Day(DAY)]);
	let json = std::fs::read(files(dir.path(), Day(DAY)).json).expect("json");
	let token = std::fs::read(files(dir.path(), Day(DAY)).tsr).expect("tsr");
	let stamp = crate::evidence::tsa::verify(&token, &sha256(&json), None, &[tsa.anchor])
		.expect("verifies");
	assert_eq!(stamp.gen_time, at(DAY + 1, 0));
	assert!(unstamped(dir.path()).expect("unstamped").is_empty());
	assert!(waiting(dir.path()).expect("waiting").is_empty());
}

#[tokio::test]
async fn a_failure_waits_with_backoff_and_is_shown() {
	let dir = sealed_day();
	let tsa = Arc::new({
		let mut tsa = FakeTsa::new(at(DAY + 1, 0));
		tsa.faults.refuse = Some(2);
		tsa
	});
	let url = Arc::clone(&tsa).serve().await;
	let settings = settings(url, &tsa);
	let now = at(DAY + 1, 0);
	let pass = stamp_due(dir.path(), &settings, now).await.expect("pass");
	assert_eq!(pass.failed, vec![Day(DAY)]);
	let state = waiting(dir.path()).expect("waiting");
	let entry = &state[&Day(DAY).name()];
	assert_eq!(entry.attempts, 1);
	assert_eq!(entry.next_attempt, now + FIRST_RETRY);
	assert!(
		entry
			.last_error
			.ends_with("the TSA refused the request (status 2)")
	);
	// Not due yet: nothing is sent.
	let quiet = stamp_due(dir.path(), &settings, now + FIRST_RETRY - 1)
		.await
		.expect("pass");
	assert_eq!(quiet, Pass::default());
	assert_eq!(tsa.received.lock().expect("lock").len(), 1);
	let again = stamp_due(dir.path(), &settings, now + FIRST_RETRY)
		.await
		.expect("pass");
	assert_eq!(again.failed, vec![Day(DAY)]);
	assert_eq!(
		waiting(dir.path()).expect("waiting")[&Day(DAY).name()].attempts,
		2
	);
}

#[tokio::test]
async fn a_settings_file_saying_off_does_not_stop_a_checkpoint_that_expects_a_token() {
	// The mode comes from the chain (the checkpoint says enabled); a file
	// edited to say otherwise must not leave the day unstamped.
	let dir = sealed_day();
	let tsa = Arc::new(FakeTsa::new(at(DAY + 1, 0)));
	let url = Arc::clone(&tsa).serve().await;
	let mut settings = settings(url, &tsa);
	settings.enabled = false;
	let pass = stamp_due(dir.path(), &settings, at(DAY + 1, 0))
		.await
		.expect("pass");
	assert_eq!(pass.stamped, vec![Day(DAY)]);
}

#[test]
fn backoff_doubles_from_five_minutes_to_six_hours() {
	assert_eq!(backoff(1), 300);
	assert_eq!(backoff(2), 600);
	assert_eq!(backoff(3), 1200);
	assert_eq!(backoff(8), MAX_RETRY);
	assert_eq!(backoff(u32::MAX), MAX_RETRY);
}
