//! The hold map stays bounded without ever letting a hold slip: no hold in
//! force or remembered gives way to a flood of new destinations, one
//! sender cannot take the room every other sender's holds need, a
//! destination that finds no room is held through its sender instead of
//! being left free, and the backoff keeps growing until a delivery or a
//! week of quiet.

use super::*;

const SENDER: &str = "account:flood";

fn hold(
	holds: &mut DestinationHolds,
	steps: &[u64],
	key: &str,
	sender: &str,
	now: u64,
) -> (String, DestinationHold) {
	record_hold(holds, steps, (key, sender), "421 busy", now)
}

/// The holds of destinations, leaving out those of senders.
fn destinations(holds: &DestinationHolds) -> usize {
	holds
		.keys()
		.filter(|key| !key.starts_with("sender:"))
		.count()
}

#[test]
fn one_sender_fills_its_own_share_of_the_holds_and_no_more() {
	let steps = [86_400];
	let mut holds = DestinationHolds::new();
	for n in 0..(MAX_HOLDS * 3) {
		hold(&mut holds, &steps, &format!("d{n}.example"), SENDER, 1000);
	}
	assert_eq!(destinations(&holds), MAX_HOLDS_PER_SENDER);
	assert!(
		is_held(&holds, &sender_key(SENDER), 2000),
		"the sender that filled its share waits itself"
	);
	assert_eq!(holds.len(), MAX_HOLDS_PER_SENDER + 1);

	let (key, _) = hold(
		&mut holds,
		&steps,
		"throttled.example",
		"account:other",
		1000,
	);
	assert_eq!(
		key, "throttled.example",
		"another sender's destination is held"
	);
	assert!(is_held(&holds, "throttled.example", 2000));
	assert!(!is_held(&holds, &sender_key("account:other"), 2000));
}

#[test]
fn a_flood_of_destinations_never_frees_or_resets_a_hold() {
	let steps = [60, 300, 900];
	let mut holds = DestinationHolds::new();
	hold(
		&mut holds,
		&steps,
		"throttled.example",
		"account:victim",
		1000,
	);
	// Many senders flood the map until it is full; the victim's hold has
	// run out by then, but is remembered.
	for n in 0..(MAX_HOLDS * 2) {
		let sender = format!("account:s{}", n % 8);
		hold(
			&mut holds,
			&[86_400],
			&format!("d{n}.example"),
			&sender,
			2000,
		);
	}
	assert_eq!(destinations(&holds), MAX_HOLDS);
	assert!(holds.contains_key("throttled.example"), "never evicted");

	// A quiet sender's new destination is still held: one of the flooding
	// senders gives up one of its own holds for it.
	let flooders_before = holds
		.values()
		.filter(|hold| hold.sender.as_deref() != Some("account:victim"))
		.count();
	let (key, _) = hold(&mut holds, &steps, "new.example", "account:s9", 3000);
	assert_eq!(key, "new.example");
	assert!(is_held(&holds, "new.example", 3000));
	assert!(
		!holds.contains_key("sender:account:s9"),
		"the quiet sender is not held"
	);
	assert_eq!(destinations(&holds), MAX_HOLDS);
	let flooders_after = holds
		.values()
		.filter(|hold| {
			!matches!(
				hold.sender.as_deref(),
				Some("account:victim" | "account:s9")
			)
		})
		.count();
	assert_eq!(flooders_after, flooders_before - 1);
	assert!(
		holds.contains_key("throttled.example"),
		"the victim keeps its hold"
	);
	// The victim's next deferral continues its run of steps.
	let (_, next) = hold(
		&mut holds,
		&steps,
		"throttled.example",
		"account:victim",
		3000,
	);
	assert_eq!((next.level, next.until), (1, 3300));
}

#[test]
fn the_backoff_keeps_growing_when_a_hold_runs_out_without_a_delivery() {
	let steps = [60, 300, 900];
	let mut holds = DestinationHolds::new();
	hold(&mut holds, &steps, "a.example", SENDER, 1000);
	// A deferral a day after the hold ended is still the next in a row.
	let (_, second) = hold(&mut holds, &steps, "a.example", SENDER, 87_400);
	assert_eq!((second.level, second.until), (1, 87_700));
}

#[test]
fn a_hold_is_forgotten_a_week_after_it_ran_out() {
	let mut holds = DestinationHolds::new();
	hold(&mut holds, &[60, 300], "a.example", SENDER, 1000);
	let later = 1060 + HOLD_MEMORY_SECS;
	let (_, fresh) = hold(&mut holds, &[60, 300], "a.example", SENDER, later);
	assert_eq!(fresh.level, 0);
	assert_eq!(fresh.since, later);
}

#[test]
fn a_delivery_ends_a_hold_only_once_it_has_run_out() {
	let mut holds = DestinationHolds::new();
	hold(&mut holds, &[60], "a.example", SENDER, 1000);
	assert!(!clear_after_success(&mut holds, "a.example", 1030));
	assert!(is_held(&holds, "a.example", 1030));
	assert!(clear_after_success(&mut holds, "a.example", 1060));
	assert!(holds.is_empty());
}

#[test]
fn an_oversized_key_holds_its_sender() {
	let mut holds = DestinationHolds::new();
	let long = format!("{}.example", "a".repeat(MAX_KEY_BYTES));
	let (key, _) = hold(&mut holds, &[60], &long, SENDER, 1000);
	assert_eq!(key, sender_key(SENDER));
	assert_eq!(holds.keys().collect::<Vec<_>>(), [&sender_key(SENDER)]);
}

#[test]
fn a_hold_that_ran_out_goes_once_no_mail_waits_for_it() {
	let mut holds = DestinationHolds::new();
	for key in [
		"idle.example",
		"waiting.example",
		"mx:mx.idle.example",
		"sender:system",
	] {
		hold(&mut holds, &[60], key, SENDER, 1000);
	}
	hold(&mut holds, &[86_400], "busy.example", SENDER, 1000);

	prune_idle(&mut holds, |key| key == "waiting.example", 1100);

	assert_eq!(
		holds.keys().collect::<Vec<_>>(),
		["busy.example", "mx:mx.idle.example", "waiting.example"],
		"in force, an exchanger, or mail waits"
	);
}
