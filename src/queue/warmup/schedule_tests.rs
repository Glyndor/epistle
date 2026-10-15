use super::*;
use crate::storage::{DeliveryOutcome, DeliveryRecord};

const DAY: i64 = 20_375;
const GMAIL_MX: &str = "gmail-smtp-in.l.google.com";

/// A tally of `group`'s day with `attempted` recipients, of which the first
/// `deferred` were deferred for rate and the next `spam` refused as spam.
fn day_of(attempted: u32, deferred: u32, spam: u32) -> DayTally {
	let mut tally = DayTally::default();
	for n in 0..attempted {
		let (outcome, reply) = if n < deferred {
			(DeliveryOutcome::Deferred, "421 4.7.0 slow down")
		} else if n < deferred + spam {
			(DeliveryOutcome::Failed, "550 5.7.1 spam")
		} else {
			(DeliveryOutcome::Delivered, "250 OK")
		};
		tally.add(&DeliveryRecord {
			time: 0,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "alice@sender.example".into(),
			recipient: format!("user{n}@gmail.com"),
			outcome,
			remote: Some(GMAIL_MX.into()),
			reply: Some(reply.into()),
			attempt: 1,
			extra: Default::default(),
		});
	}
	tally
}

/// A state whose Gmail group sent `sent` at `cap` on [`DAY`].
fn state(cap: Option<u32>, sent: u32) -> State {
	let mut state = State::new(DAY);
	let gmail = state.group_mut(Group::Gmail);
	gmail.cap = cap;
	gmail.sent = sent;
	state
}

fn gmail(events: &[Event]) -> (EventKind, Option<u32>, Option<u32>, Verdict) {
	let event = events
		.iter()
		.find(|event| event.group == Group::Gmail)
		.expect("a gmail event");
	(
		event.kind,
		event.record.cap,
		event.record.next_cap,
		event.record.verdict,
	)
}

#[test]
fn a_good_full_day_grows_the_cap() {
	let mut state = state(Some(50), 50);
	let events = close_day(&mut state, DAY, &day_of(50, 0, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Ok, Some(50), Some(75), Verdict::Good)
	);
	assert_eq!(events.len(), 1, "groups that sent nothing are not reported");
	assert_eq!(state.group(Group::Gmail).cap, Some(75));
	assert_eq!(state.group(Group::Gmail).history.len(), 1);
}

#[test]
fn a_good_day_with_too_little_mail_keeps_the_cap() {
	let mut state = state(Some(50), 10);
	let events = close_day(&mut state, DAY, &day_of(10, 0, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Ok, Some(50), Some(50), Verdict::Good)
	);
}

#[test]
fn a_bad_day_holds_and_a_very_bad_day_goes_back_a_step() {
	let mut held = state(Some(113), 113);
	let events = close_day(&mut held, DAY, &day_of(100, 5, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Held, Some(113), Some(113), Verdict::Bad)
	);

	let mut deferred = state(Some(113), 113);
	let events = close_day(&mut deferred, DAY, &day_of(100, 11, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Backoff, Some(113), Some(75), Verdict::VeryBad)
	);

	let mut blocked = state(Some(113), 113);
	let events = close_day(&mut blocked, DAY, &day_of(100, 0, 1), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Backoff, Some(113), Some(75), Verdict::VeryBad)
	);
	let record = &blocked.group(Group::Gmail).history[0];
	assert_eq!(
		(record.attempted, record.deferred, record.spam_blocks),
		(100, 0, 1)
	);
}

#[test]
fn a_paused_schedule_reports_the_day_and_moves_nothing() {
	let mut state = state(Some(50), 50);
	let events = close_day(&mut state, DAY, &day_of(50, 20, 0), true);
	assert_eq!(
		gmail(&events),
		(EventKind::Backoff, Some(50), Some(50), Verdict::VeryBad)
	);
	assert!(events[0].record.paused);
}

#[test]
fn a_day_no_remote_answered_is_kept_but_not_reported() {
	let mut state = state(Some(50), 5);
	let events = close_day(&mut state, DAY, &DayTally::default(), false);
	assert!(events.is_empty());
	let history = &state.group(Group::Gmail).history;
	assert_eq!(
		(history.len(), history[0].verdict, history[0].next_cap),
		(1, Verdict::Idle, Some(50))
	);
}

#[test]
fn a_raise_is_judged_on_its_trial_day_and_kept_when_it_goes_well() {
	let mut state = state(Some(50), 0);
	apply(state.group_mut(Group::Gmail), Action::Set { cap: 200 }, DAY);
	assert_eq!(
		state.group(Group::Gmail).raise,
		Some(Raise {
			from: 50,
			trial_day: DAY + 1
		})
	);
	// The rest of the day the raise was given on decides nothing.
	state.group_mut(Group::Gmail).sent = 120;
	let events = close_day(&mut state, DAY, &day_of(120, 0, 0), false);
	assert_eq!(events[0].record.raise, Some(RaiseOutcome::Pending));
	assert_eq!(state.group(Group::Gmail).cap, Some(200));
	open_day(&mut state, DAY + 1);
	state.group_mut(Group::Gmail).sent = 200;
	let events = close_day(&mut state, DAY + 1, &day_of(200, 1, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Ok, Some(200), Some(200), Verdict::Good)
	);
	assert_eq!(events[0].record.raise, Some(RaiseOutcome::Kept));
	assert_eq!(state.group(Group::Gmail).raise, None);
}

#[test]
fn a_raise_that_goes_badly_is_reverted_and_reported_as_a_backoff() {
	let mut state = state(Some(75), 0);
	apply(state.group_mut(Group::Gmail), Action::Set { cap: 300 }, DAY);
	// A second raise before the trial still goes back to where it all began.
	apply(state.group_mut(Group::Gmail), Action::Set { cap: 400 }, DAY);
	open_day(&mut state, DAY + 1);
	state.group_mut(Group::Gmail).sent = 400;
	let events = close_day(&mut state, DAY + 1, &day_of(400, 12, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Backoff, Some(400), Some(75), Verdict::Bad)
	);
	assert_eq!(events[0].record.raise, Some(RaiseOutcome::Reverted));
}

#[test]
fn a_trial_day_without_mail_leaves_the_raise_on_trial() {
	let mut state = state(Some(50), 0);
	apply(state.group_mut(Group::Gmail), Action::Next, DAY);
	assert_eq!(state.group(Group::Gmail).cap, Some(75));
	open_day(&mut state, DAY + 1);
	assert!(close_day(&mut state, DAY + 1, &DayTally::default(), false).is_empty());
	open_day(&mut state, DAY + 2);
	state.group_mut(Group::Gmail).sent = 75;
	let events = close_day(&mut state, DAY + 2, &day_of(75, 0, 0), false);
	assert_eq!(events[0].record.raise, Some(RaiseOutcome::Kept));
}

#[test]
fn lowering_the_cap_and_starting_over_are_not_on_trial() {
	let mut schedule = GroupState {
		cap: Some(500),
		tat_ms: 99,
		..GroupState::default()
	};
	apply(&mut schedule, Action::Set { cap: 100 }, DAY);
	assert_eq!((schedule.cap, schedule.raise), (Some(100), None));
	schedule.cap = None;
	apply(&mut schedule, Action::Next, DAY);
	assert_eq!(schedule.cap, None, "a warmed-up group has no next step");
	apply(&mut schedule, Action::Reset, DAY);
	assert_eq!(
		(schedule.cap, schedule.raise, schedule.tat_ms),
		(Some(START_CAP), None, 0)
	);
}

#[test]
fn a_warmed_up_group_is_reported_and_stays_uncapped() {
	let mut state = state(None, 900);
	let events = close_day(&mut state, DAY, &day_of(900, 200, 0), false);
	assert_eq!(
		gmail(&events),
		(EventKind::Backoff, None, None, Verdict::VeryBad)
	);
}

#[test]
fn a_new_day_starts_every_count_at_zero() {
	let mut state = state(Some(50), 50);
	state
		.group_mut(Group::Gmail)
		.senders
		.insert("system".into(), 50);
	open_day(&mut state, DAY + 1);
	let gmail = state.group(Group::Gmail);
	assert_eq!(
		(state.day, gmail.sent, gmail.senders.len()),
		(DAY + 1, 0, 0)
	);
}

#[test]
fn a_bad_day_names_the_accounts_behind_it() {
	let mut tally = day_of(100, 0, 0);
	for n in 0..4 {
		tally.add(&DeliveryRecord {
			time: 0,
			spool_id: uuid::Uuid::nil(),
			account: Some("bulk@school.example".into()),
			from: "bulk@school.example".into(),
			recipient: format!("dead{n}@gmail.com"),
			outcome: DeliveryOutcome::Failed,
			remote: Some(GMAIL_MX.into()),
			reply: Some("550 5.1.1 unknown".into()),
			attempt: 1,
			extra: Default::default(),
		});
	}
	let mut state = state(Some(50), 50);
	let events = close_day(&mut state, DAY, &tally, false);
	assert_eq!(
		gmail(&events),
		(EventKind::Held, Some(50), Some(50), Verdict::Bad)
	);
	assert_eq!(
		events[0].record.causes,
		[crate::queue::warmup::state::Cause {
			account: "bulk@school.example".into(),
			bad: 4
		}]
	);
}
