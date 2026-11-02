//! A DNS failure after a certificate change is not forgotten: the owed
//! publication is kept, retried with a growing wait, and cleared when the
//! provider accepts it.

use std::time::Duration;

use super::support::{HOST, Zone, certificate};
use super::*;
use crate::dns::provider::ProviderError;

fn target<'a>(zone: &'a Zone, dir: &'a Path) -> Target<'a> {
	Target {
		provider: Some(zone),
		hostname: HOST,
		data_dir: dir,
	}
}

fn refused() -> ProviderError {
	ProviderError::Remote("the provider is down".to_string())
}

#[tokio::test]
async fn a_failed_publication_is_kept_as_pending() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (pem, value) = certificate();

	let outcome = refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	match outcome {
		Outcome::Pending {
			value: owed,
			attempts,
			retry_in,
			..
		} => {
			assert_eq!(owed, value, "the association of the new certificate");
			assert_eq!(attempts, 1);
			assert_eq!(retry_in, Duration::from_secs(60));
		}
		other => panic!("a refused write stays pending, got {other:?}"),
	}
	let state = State::load(dir.path(), HOST);
	let pending = state.pending.expect("the owed publication is stored");
	assert_eq!(pending.value, value);
	assert_eq!(pending.since, 1_000);
	assert_eq!(pending.next_attempt, 1_060);
}

#[tokio::test]
async fn the_owed_publication_survives_the_watcher_marking_the_files_loaded() {
	// The watcher compares stamps and reports Unchanged on the next tick; the
	// retry must not depend on it. It reads the state, not the stamps.
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (pem, value) = certificate();
	refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	zone.fail_with(None);
	let outcome = retry_due(&target(&zone, dir.path()), &pem, 1_060)
		.await
		.expect("the wait is over");

	assert_eq!(
		outcome,
		Outcome::Published {
			value: value.clone()
		}
	);
	assert_eq!(zone.values(), vec![value]);
	assert!(
		State::load(dir.path(), HOST).pending.is_none(),
		"a published record clears what was owed"
	);
}

#[tokio::test]
async fn nothing_is_tried_before_the_wait_is_over() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (pem, _) = certificate();
	refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;
	zone.fail_with(None);

	let early = retry_due(&target(&zone, dir.path()), &pem, 1_059).await;

	assert!(early.is_none(), "one second early is still waiting");
	assert_eq!(zone.writes(), 0, "no write went out");
}

#[test]
fn the_wait_doubles_up_to_an_hour() {
	assert_eq!(wait_after(1), Duration::from_secs(60));
	assert_eq!(wait_after(2), Duration::from_secs(120));
	assert_eq!(wait_after(3), Duration::from_secs(240));
	assert_eq!(wait_after(7), Duration::from_secs(3600));
	assert_eq!(wait_after(u32::MAX), Duration::from_secs(3600));
}

#[tokio::test]
async fn a_second_failure_counts_the_attempt_and_keeps_the_first_date() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (pem, _) = certificate();
	refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	retry_due(&target(&zone, dir.path()), &pem, 1_060)
		.await
		.expect("due");

	let pending = State::load(dir.path(), HOST).pending.expect("pending");
	assert_eq!(pending.attempts, 2);
	assert_eq!(pending.since, 1_000, "owed since the first failure");
	assert_eq!(pending.next_attempt, 1_060 + 120);
}

#[tokio::test]
async fn a_renewed_certificate_replaces_the_owed_one() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (old_pem, old_value) = certificate();
	refresh(&target(&zone, dir.path()), &old_pem, None, 1_000).await;

	let (new_pem, new_value) = certificate();
	zone.fail_with(None);
	retry_due(&target(&zone, dir.path()), &new_pem, 1_060)
		.await
		.expect("due");

	assert_eq!(zone.values(), vec![new_value], "the certificate in service");
	assert!(!zone.values().contains(&old_value));
}

#[tokio::test]
async fn a_provider_that_cannot_write_leaves_the_record_to_the_operator() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(ProviderError::Unsupported));
	let (pem, value) = certificate();

	let outcome = refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	assert_eq!(outcome, Outcome::ByHand { value });
	assert!(
		State::load(dir.path(), HOST).pending.is_none(),
		"nothing to retry: the provider will never accept it"
	);
}

#[tokio::test]
async fn no_provider_means_by_hand_and_a_chain_without_certificate_means_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, value) = certificate();
	let none = Target {
		provider: None,
		hostname: HOST,
		data_dir: dir.path(),
	};
	assert_eq!(
		refresh(&none, &pem, None, 1).await,
		Outcome::ByHand { value }
	);
	assert_eq!(
		refresh(&none, "garbage", None, 1).await,
		Outcome::NoCertificate
	);
}

#[tokio::test]
async fn a_state_for_another_host_is_not_ours() {
	let dir = tempfile::tempdir().expect("dir");
	let zone = Zone::empty();
	zone.fail_with(Some(refused()));
	let (pem, _) = certificate();
	refresh(&target(&zone, dir.path()), &pem, None, 1_000).await;

	assert!(
		State::load(dir.path(), "other.example.net")
			.pending
			.is_none()
	);
}
