
use super::*;

#[test]
fn rate_limit_replies_hold_the_destination() {
	for reason in [
		"421 4.7.0 Try again later, closing connection",
		"421 mx.example.com service not available",
		"450 4.7.1 Client host rejected: too many connections",
		"451 4.7.650 The mail server has been temporarily rate limited",
		"451 Too many messages, slow down",
		"452 4.3.1 Rate limit exceeded",
	] {
		assert!(throttled(reason), "{reason}");
	}
}

#[test]
fn other_deferrals_do_not_hold_the_destination() {
	for reason in [
		"452 4.5.3 too many recipients",
		"452 too many recipients",
		"452 4.2.2 mailbox full",
		"451 4.3.0 try again later",
		"450 4.2.0 mailbox busy",
		"timed out after 300s waiting for the greeting",
		"connection refused",
	] {
		assert!(!throttled(reason), "{reason}");
	}
}

#[test]
fn too_many_recipients_is_its_own_case() {
	assert!(too_many_recipients("452 4.5.3 too many recipients"));
	assert!(too_many_recipients("452 Too many recipients"));
	assert!(!too_many_recipients("452 4.2.2 mailbox full"));
	assert!(!too_many_recipients("451 4.5.3 too many recipients"));
}

#[test]
fn the_steps_grow_and_stay_at_the_last() {
	let steps = [60, 300, 900];
	assert_eq!(
		(0..5).map(|level| step(&steps, level)).collect::<Vec<_>>(),
		[60, 300, 900, 900, 900]
	);
	assert_eq!(step(&[], 0), DEFAULT_STEPS[0]);
}
