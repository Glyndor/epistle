//! Per-recipient state of a spooled envelope.

use super::*;

fn envelope(recipients: &[&str], attempts: u32, next_attempt: u64) -> Envelope {
	serde_json::from_value(serde_json::json!({
		"id": uuid::Uuid::now_v7(),
		"reverse_path": "alice@example.org",
		"recipients": recipients,
		"attempts": attempts,
		"next_attempt": next_attempt,
	}))
	.expect("envelope")
}

#[test]
fn an_entry_without_state_reads_as_all_pending_with_its_schedule() {
	let envelope = envelope(&["bob@a.example", "dan@b.example"], 3, 900);
	assert_eq!(envelope.pending().len(), 2);
	let dan = envelope.recipient_state("dan@b.example");
	assert_eq!((dan.attempts, dan.next_attempt), (3, 900));
}

#[test]
fn one_recipient_record_does_not_change_another_recipient_schedule() {
	let mut envelope = envelope(&["bob@a.example", "dan@b.example"], 0, 0);
	let mut bob = envelope.recipient_state("bob@a.example");
	bob.attempts = 1;
	bob.next_attempt = 500;
	envelope.set_recipient_state("bob@a.example", bob);
	envelope.settle();

	let dan = envelope.recipient_state("dan@b.example");
	assert_eq!(
		(dan.attempts, dan.next_attempt),
		(0, 0),
		"dan@ has not been attempted"
	);
}
