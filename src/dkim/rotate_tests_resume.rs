//! Resuming a journaled rotation in the cases a plain restart does not
//! cover: a later day, a key file that does not load, a configuration that
//! lost a domain, an operator request, a withdrawal the provider refuses,
//! temporary files a killed write left behind, and a torn state file.

use super::steps::Step;
use super::tests_crash::{DAY, DOMAINS, Lab, NOW, Start, Visibility, crash, crash_and_restart};
use super::*;
use std::sync::atomic::Ordering;

fn pending(lab: &Lab) -> Option<Pending> {
	read_state(&lab.root)
		.expect("state")
		.expect("state")
		.pending
}

#[tokio::test]
async fn a_later_day_finishes_the_journaled_selector_with_its_key() {
	let lab = Lab::new(Start::RotationDue);
	crash(&lab, Step::Published(0), Visibility::AfterOneWait).await;
	let key = std::fs::read(lab.root.join("dkim-ed100.key")).expect("journaled key");
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	rotator.tick(NOW + 2 * DAY).await.expect("resume");
	lab.assert_settled(&signer, "ed100", Some("ed0")).await;
	assert_eq!(
		std::fs::read(lab.root.join("dkim-ed100.key")).expect("key"),
		key,
		"the key that may already be published is kept, not regenerated"
	);
}

#[tokio::test]
async fn a_journaled_key_that_does_not_load_is_written_again() {
	let lab = Lab::new(Start::RotationDue);
	crash(&lab, Step::KeyWritten, Visibility::AfterOneWait).await;
	std::fs::write(lab.root.join("dkim-ed100.key"), "-----BEGIN PRIV").expect("tear key");
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	rotator.tick(NOW + 60).await.expect("resume");
	lab.assert_settled(&signer, "ed100", Some("ed0")).await;
}

#[tokio::test]
async fn a_domain_dropped_while_pending_loses_the_new_record() {
	let lab = Lab::new(Start::RotationDue);
	crash(&lab, Step::Published(1), Visibility::AfterOneWait).await;
	let (signer, rotator) = lab.start_with(Visibility::AfterOneWait, &DOMAINS[..1]);
	rotator.tick(NOW + 60).await.expect("resume");
	let names: Vec<String> = lab.zone.records.lock().unwrap().keys().cloned().collect();
	assert!(
		!names.contains(&format!("ed100._domainkey.{}", DOMAINS[1])),
		"no record of the new selector is left at the dropped domain: {names:?}"
	);
	assert!(names.contains(&format!("ed100._domainkey.{}", DOMAINS[0])));
	assert!(pending(&lab).is_none(), "the rotation is committed");
	lab.assert_verifies(&signer, "after the resume").await;
}

#[tokio::test]
async fn an_operator_request_finishes_the_pending_rotation_first() {
	let lab = Lab::new(Start::RotationDue);
	crash(&lab, Step::Waiting, Visibility::AfterOneWait).await;
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	rotator.force_rotate(NOW + 60).await.expect("resume");
	lab.assert_settled(&signer, "ed100", Some("ed0")).await;
}

#[tokio::test]
async fn a_refused_withdrawal_stays_journaled_until_it_lands() {
	let lab = Lab::new(Start::RotationDue);
	lab.zone.refuse_deletes.store(true, Ordering::SeqCst);
	let (signer, rotator) = lab.start(Visibility::Never);
	let error = rotator.tick(NOW).await.expect_err("withdrawal refused");
	assert!(
		error.to_string().contains("retried at the next tick"),
		"{error}"
	);
	let journal = pending(&lab).expect("still journaled");
	assert!(
		journal
			.withdrawing
			.as_deref()
			.is_some_and(|reason| reason.contains("does not show the new key")),
		"{journal:?}"
	);
	lab.assert_verifies(&signer, "while the withdrawal waits")
		.await;

	// Publishing must not start again: the next tick only removes.
	lab.zone.refuse_deletes.store(false, Ordering::SeqCst);
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	let error = rotator.tick(NOW + 60).await.expect_err("withdrawn");
	assert!(error.to_string().contains("withdrawn"), "{error}");
	lab.assert_settled(&signer, "ed0", None).await;
}

#[tokio::test]
async fn a_withdrawal_after_a_restart_is_still_reported() {
	let lab = Lab::new(Start::RotationDue);
	crash_and_restart(&lab, Step::Withdrawing, Visibility::Never).await;
	let report = std::fs::read_to_string(lab.root.join(ERROR_FILE)).expect("error file");
	assert!(
		report.contains("rotation to ed100 withdrawn")
			&& report.contains("does not show the new key"),
		"the reason recorded before the crash is the one reported: {report}"
	);
}

#[tokio::test]
async fn temporary_files_of_killed_writes_are_swept() {
	let lab = Lab::new(Start::RotationDue);
	let stale = [
		".dkim-rotation.json.0190f3a1.tmp",
		".dkim-ed100.key.0190f3a1.tmp",
		"dkim-rotation.json.tmp",
	];
	let kept = ["dkim-rotate.tmp", ".accounts.toml.0190f3a1.tmp"];
	for name in stale.iter().chain(&kept) {
		std::fs::write(lab.root.join(name), "x").expect("temp file");
	}
	let (_signer, rotator) = lab.start(Visibility::AfterOneWait);
	rotator.tick(NOW).await.expect("rotate");
	for name in stale {
		assert!(!lab.root.join(name).exists(), "{name} is swept");
	}
	for name in kept {
		assert!(
			lab.root.join(name).exists(),
			"{name} belongs to someone else"
		);
	}
}

#[tokio::test]
async fn a_torn_state_signs_with_the_last_good_one_and_stops_rotating() {
	let lab = Lab::new(Start::RotationDue);
	let (_signer, rotator) = lab.start(Visibility::AfterOneWait);
	rotator.tick(NOW).await.expect("rotate");
	let bytes = std::fs::read(lab.root.join(STATE_FILE)).expect("state");
	let torn = &bytes[..bytes.len() / 2];
	std::fs::write(lab.root.join(STATE_FILE), torn).expect("tear");
	assert!(
		state_fallback(&lab.root).is_some_and(|error| error.contains(STATE_FILE)),
		"the fallback is reported with the reason"
	);

	// Startup still signs, with the state one save behind: the journal
	// entry whose active key ed0 keeps its TXT through the overlap.
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	assert_eq!(signer.current().selector(), "ed0");
	lab.assert_verifies(&signer, "with the last good state")
		.await;

	// Rotation does not guess: it stops and leaves the file to the operator.
	let error = rotator.tick(NOW + DAY).await.expect_err("rotation stops");
	assert!(error.to_string().contains(STATE_FILE), "{error}");
	assert_eq!(
		std::fs::read(lab.root.join(STATE_FILE)).expect("state"),
		torn
	);
}
