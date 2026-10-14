//! The hold map stays bounded without ever letting a hold slip: no hold in
//! force or remembered gives way to a flood of new destinations, one
//! sender cannot take the room every other sender's holds need, and the
//! backoff keeps growing until a delivery or a week of quiet.

use super::*;

const SENDER: &str = "account:flood";

fn hold(
	holds: &mut DestinationHolds,
	steps: &[u64],
	key: &str,
	sender: &str,
	now: u64,
) -> Option<DestinationHold> {
	record_hold(holds, steps, (key, sender), "421 busy", now)
}

#[test]
fn one_sender_fills_its_own_share_of_the_holds_and_no_more() {
	let steps = [86_400];
	let mut holds = DestinationHolds::new();
	for n in 0..(MAX_HOLDS * 3) {
		hold(&mut holds, &steps, &format!("d{n}.example"), SENDER, 1000);
	}
	assert_eq!(holds.len(), MAX_HOLDS_PER_SENDER);

	let other = hold(
		&mut holds,
		&steps,
		"throttled.example",
		"account:other",
		1000,
	);
	assert!(
		other.is_some(),
		"another sender's destination is still held"
	);
	assert!(is_held(&holds, "throttled.example", 2000));
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
	assert_eq!(holds.len(), MAX_HOLDS);
	assert!(holds.contains_key("throttled.example"), "never evicted");

	// A new destination finds no room and is not held at all.
	assert_eq!(
		hold(&mut holds, &steps, "new.example", "account:s9", 3000),
		None
	);
	// The victim's next deferral continues its run of steps.
	let next = hold(
		&mut holds,
		&steps,
		"throttled.example",
		"account:victim",
		3000,
	)
	.expect("hold");
	assert_eq!((next.level, next.until), (1, 3300));
}

#[test]
fn the_backoff_keeps_growing_when_a_hold_runs_out_without_a_delivery() {
	let steps = [60, 300, 900];
	let mut holds = DestinationHolds::new();
	hold(&mut holds, &steps, "a.example", SENDER, 1000);
	// A deferral a day after the hold ended is still the next in a row.
	let second = hold(&mut holds, &steps, "a.example", SENDER, 87_400).expect("hold");
	assert_eq!((second.level, second.until), (1, 87_700));
}

#[test]
fn a_hold_is_forgotten_a_week_after_it_ran_out() {
	let mut holds = DestinationHolds::new();
	hold(&mut holds, &[60, 300], "a.example", SENDER, 1000);
	let later = 1060 + HOLD_MEMORY_SECS;
	let fresh = hold(&mut holds, &[60, 300], "a.example", SENDER, later).expect("hold");
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
