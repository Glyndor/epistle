use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::queue::warmup::policy::Verdict;
use crate::queue::warmup::settings::Action;
use crate::storage::{DeliveryOutcome, DeliveryRecord};

/// Midnight UTC of the test day.
const MIDNIGHT: u64 = 20_375 * 86_400;
const GMAIL_MX: &str = "gmail-smtp-in.l.google.com";

pub(super) fn enable(dir: &Path, change: impl FnOnce(&mut Settings)) {
	let mut settings = settings::load(dir).expect("load").unwrap_or_default();
	settings.enabled = true;
	change(&mut settings);
	settings::save(dir, &settings).expect("save");
}

fn on(dir: &Path, now: u64) -> Warmup {
	enable(dir, |_| {});
	Warmup::open(dir, Some(DeliveryLog::open(dir, 30)), now)
}

pub(super) fn granted(grant: Grant) -> (usize, u64) {
	match grant {
		Grant::Limited { granted, until } => (granted, until),
		Grant::Unlimited => panic!("expected a cap"),
	}
}

#[test]
fn off_by_default_and_every_recipient_goes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = Warmup::open(dir.path(), None, MIDNIGHT);
	assert!(!warmup.enabled());
	assert_eq!(
		warmup.grant(Group::Gmail, "system", 1000, MIDNIGHT),
		Grant::Unlimited
	);
	assert_eq!(warmup.blocked(Group::Gmail, "system", MIDNIGHT), None);
	assert!(
		!state::path(dir.path()).exists(),
		"an install that never turned it on writes nothing"
	);
}

#[test]
fn a_cap_lets_the_burst_go_then_paces_the_rest() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "account:sena", 1000, MIDNIGHT)),
		(3, MIDNIGHT + 1728)
	);
	assert_eq!(
		warmup.blocked(Group::Gmail, "account:sena", MIDNIGHT + 100),
		Some(MIDNIGHT + 1728)
	);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "account:sena", 5, MIDNIGHT + 1728)),
		(1, MIDNIGHT + 2 * 1728)
	);
	// Another group has its own cap.
	assert_eq!(
		granted(warmup.grant(Group::Outlook, "account:sena", 2, MIDNIGHT)),
		(2, MIDNIGHT)
	);
}

#[test]
fn the_day_never_goes_past_the_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	let mut sent = 0;
	for minute in 0..(24 * 60) {
		let now = MIDNIGHT + minute * 60;
		for sender in ["account:a", "account:b", "system"] {
			sent += granted(warmup.grant(Group::Gmail, sender, 100, now)).0;
		}
	}
	assert_eq!(sent, 50);
}

#[test]
fn what_was_let_through_survives_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	granted(warmup.grant(Group::Gmail, "account:sena", 3, MIDNIGHT));
	drop(warmup);
	let again = Warmup::open(dir.path(), None, MIDNIGHT + 10);
	assert_eq!(
		granted(again.grant(Group::Gmail, "account:sena", 3, MIDNIGHT + 10)),
		(0, MIDNIGHT + 1728)
	);
	let (_, state) = again.snapshot();
	assert_eq!(state.group(Group::Gmail).sent, 3);
}

#[test]
fn recipients_never_offered_are_given_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	granted(warmup.grant(Group::Gmail, "system", 3, MIDNIGHT));
	warmup.give_back(Group::Gmail, "system", 3, MIDNIGHT + 1);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 3, MIDNIGHT + 2)),
		(3, MIDNIGHT + 2)
	);
	let (_, state) = warmup.snapshot();
	assert_eq!(state.group(Group::Gmail).sent, 3);
}

#[test]
fn a_share_that_cannot_be_recorded_is_not_given() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	let data = dir.path();
	std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o500)).expect("chmod");
	let grant = warmup.grant(Group::Gmail, "system", 3, MIDNIGHT);
	std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700)).expect("chmod");
	if nix_is_root() {
		// Root writes through the mode; the refusal cannot be staged.
		return;
	}
	assert_eq!(granted(grant), (0, MIDNIGHT + 60));
	let (_, state) = warmup.snapshot();
	assert_eq!(state.group(Group::Gmail).sent, 0, "nothing was counted");
}

fn nix_is_root() -> bool {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() == 0 }
}

#[test]
fn a_state_others_could_write_is_replaced_by_the_most_restrictive_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut lifted = State::new(20_375);
	lifted.group_mut(Group::Gmail).cap = None;
	state::save(dir.path(), &lifted).expect("save");
	std::fs::set_permissions(
		state::path(dir.path()),
		std::fs::Permissions::from_mode(0o666),
	)
	.expect("chmod");
	let warmup = on(dir.path(), MIDNIGHT);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 1, MIDNIGHT)),
		(0, MIDNIGHT + 86_400)
	);
}

#[test]
fn a_settings_file_others_could_write_keeps_the_caps_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	settings::save(dir.path(), &Settings::default()).expect("save");
	std::fs::set_permissions(
		settings::path(dir.path()),
		std::fs::Permissions::from_mode(0o666),
	)
	.expect("chmod");
	let warmup = Warmup::open(dir.path(), None, MIDNIGHT);
	assert!(warmup.enabled());
	// A reload of such a file leaves the running settings alone.
	warmup.reload(MIDNIGHT).expect_err("refused");
	assert!(warmup.enabled());
}

fn log_day(dir: &Path, delivered: u32, deferred: u32) {
	let log = DeliveryLog::open(dir, 30);
	for n in 0..(delivered + deferred) {
		let (outcome, reply) = match n < deferred {
			true => (DeliveryOutcome::Deferred, "421 4.7.0 slow down"),
			false => (DeliveryOutcome::Delivered, "250 OK"),
		};
		log.append(&DeliveryRecord {
			time: MIDNIGHT + 3600,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "alice@sender.example".into(),
			recipient: format!("user{n}@gmail.com"),
			outcome,
			remote: Some(GMAIL_MX.into()),
			reply: Some(reply.into()),
			attempt: 1,
			extra: Default::default(),
		})
		.expect("append");
	}
}

/// Use up the whole Gmail day, from several senders.
fn fill_day(warmup: &Warmup) {
	for minute in 0..(24 * 60) {
		for sender in ["account:a", "account:b"] {
			warmup.grant(Group::Gmail, sender, 100, MIDNIGHT + minute * 60);
		}
	}
}

#[test]
fn the_next_day_grows_the_cap_after_a_good_one_and_reports_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	fill_day(&warmup);
	log_day(dir.path(), 50, 0);
	warmup.tick(MIDNIGHT + 86_400 + 5);
	let (_, state) = warmup.snapshot();
	let gmail = state.group(Group::Gmail);
	assert_eq!((state.day, gmail.cap, gmail.sent), (20_376, Some(75), 0));
	assert_eq!(
		gmail.history.back().map(|day| day.verdict),
		Some(Verdict::Good)
	);
	// A restart in the new day does not judge the old one again.
	drop(warmup);
	let again = Warmup::open(dir.path(), None, MIDNIGHT + 86_400 + 10);
	again.tick(MIDNIGHT + 86_400 + 10);
	assert_eq!(again.snapshot().1.group(Group::Gmail).history.len(), 1);
}

#[test]
fn a_very_bad_day_sends_the_cap_back_and_counts_for_alerts() {
	let dir = tempfile::tempdir().expect("tempdir");
	enable(dir.path(), |_| {});
	let mut grown = State::new(20_375);
	grown.group_mut(Group::Gmail).cap = Some(113);
	state::save(dir.path(), &grown).expect("save");
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let warmup = Warmup::open(
		dir.path(),
		Some(DeliveryLog::open(dir.path(), 30)),
		MIDNIGHT,
	)
	.with_metrics(Arc::clone(&metrics));
	fill_day(&warmup);
	log_day(dir.path(), 80, 20);
	warmup.tick(MIDNIGHT + 86_400);
	assert_eq!(warmup.snapshot().1.group(Group::Gmail).cap, Some(75));
	assert_eq!(metrics.snapshot().get("warmup_backoff"), Some(&1));
}

#[test]
fn an_operator_raise_reaches_the_running_server_and_is_judged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	enable(dir.path(), |settings| {
		settings.order(Group::Gmail, Action::Set { cap: 200 });
	});
	warmup.reload(MIDNIGHT + 60).expect("reload");
	let (_, state) = warmup.snapshot();
	assert_eq!(
		(state.applied, state.group(Group::Gmail).cap),
		(1, Some(200))
	);
	// Reading the same file again applies nothing twice.
	warmup.reload(MIDNIGHT + 120).expect("reload");
	assert_eq!(
		warmup
			.snapshot()
			.1
			.group(Group::Gmail)
			.raise
			.map(|raise| raise.from),
		Some(50)
	);
	// The trial day goes badly: the raise is reverted.
	warmup.tick(MIDNIGHT + 86_400);
	for minute in 0..(24 * 60) {
		for sender in ["account:a", "account:b"] {
			warmup.grant(Group::Gmail, sender, 100, MIDNIGHT + 86_400 + minute * 60);
		}
	}
	let log = DeliveryLog::open(dir.path(), 30);
	for n in 0..100 {
		log.append(&DeliveryRecord {
			time: MIDNIGHT + 86_400 + 60,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "alice@sender.example".into(),
			recipient: format!("user{n}@gmail.com"),
			outcome: DeliveryOutcome::Deferred,
			remote: Some(GMAIL_MX.into()),
			reply: Some(match n < 5 {
				true => "421 4.7.0 slow down".into(),
				false => "450 4.2.0 greylisted".into(),
			}),
			attempt: 1,
			extra: Default::default(),
		})
		.expect("append");
	}
	warmup.tick(MIDNIGHT + 2 * 86_400);
	let gmail = warmup.snapshot().1.group(Group::Gmail);
	assert_eq!(gmail.cap, Some(50));
	assert_eq!(
		gmail.history.back().map(|day| (day.verdict, day.raise)),
		Some((Verdict::Bad, Some(state::RaiseOutcome::Reverted)))
	);
}

#[test]
fn turning_it_off_lifts_every_cap_at_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let warmup = on(dir.path(), MIDNIGHT);
	granted(warmup.grant(Group::Gmail, "system", 100, MIDNIGHT));
	assert!(warmup.blocked(Group::Gmail, "system", MIDNIGHT).is_some());
	enable(dir.path(), |settings| settings.enabled = false);
	warmup.reload(MIDNIGHT + 1).expect("reload");
	assert_eq!(warmup.blocked(Group::Gmail, "system", MIDNIGHT + 1), None);
	assert_eq!(
		warmup.grant(Group::Gmail, "system", 100, MIDNIGHT + 1),
		Grant::Unlimited
	);
}

#[test]
fn a_cap_of_zero_written_by_hand_does_not_hold_mail_for_ever() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut shut = State::new(20_375);
	shut.group_mut(Group::Gmail).cap = Some(0);
	state::save(dir.path(), &shut).expect("save");
	let warmup = on(dir.path(), MIDNIGHT);
	let tomorrow = MIDNIGHT + 86_400;
	warmup.tick(tomorrow);
	assert_eq!(
		granted(warmup.grant(Group::Gmail, "system", 1, tomorrow)),
		(1, tomorrow)
	);
}
