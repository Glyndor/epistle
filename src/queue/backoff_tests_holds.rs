//! The holds are what the spool shows: a pending recipient deferred by a
//! slow-down reply holds its domain and the exchanger that sent it until
//! its own next attempt, and nothing else holds anything.

use std::collections::BTreeMap;

use super::*;
use crate::storage::{RecipientState, RecipientStatus};

fn envelope(states: &[(&str, RecipientState)]) -> Envelope {
	let mut envelope: Envelope = serde_json::from_value(serde_json::json!({
		"id": uuid::Uuid::now_v7(),
		"reverse_path": "alice@sender.example",
		"recipients": states.iter().map(|(recipient, _)| *recipient).collect::<Vec<_>>(),
		"attempts": 0,
		"next_attempt": 0,
		"require_tls": false,
	}))
	.expect("envelope");
	envelope.recipient_state = states
		.iter()
		.map(|(recipient, state)| (recipient.to_string(), state.clone()))
		.collect::<BTreeMap<_, _>>();
	envelope
}

fn throttled(until: u64, deferrals: u32, host: &str) -> RecipientState {
	RecipientState {
		next_attempt: until,
		throttled: deferrals,
		last_error: Some("421 4.7.0 slow down".into()),
		remote: Some(host.into()),
		..RecipientState::default()
	}
}

#[test]
fn a_throttled_recipient_holds_its_domain_and_its_exchanger() {
	let mut holds = Holds::default();
	holds.add_envelope(&envelope(&[
		("a@Busy.Example", throttled(1300, 2, "MX.Provider.Example.")),
		("b@busy.example", throttled(1060, 1, "mx.provider.example")),
		("c@calm.example", RecipientState::default()),
	]));

	let busy = Destination::new("busy.example");
	let provider = Destination::new("mx.provider.example");
	assert_eq!(
		holds.held(&busy, 1100),
		Some(&Hold {
			until: 1300,
			deferrals: 2,
			reason: "421 4.7.0 slow down".into(),
		})
	);
	assert_eq!(
		holds.held(&provider, 1100).map(|hold| hold.until),
		Some(1300)
	);
	assert_eq!(holds.held(&Destination::new("calm.example"), 1100), None);
	assert_eq!(holds.held(&busy, 1300), None, "it ends at its next attempt");
	assert_eq!(
		holds.deferrals(&busy),
		2,
		"the run is remembered after the end"
	);
	assert_eq!(
		holds
			.in_force(1100)
			.into_iter()
			.map(|(destination, _)| destination.as_str())
			.collect::<Vec<_>>(),
		["busy.example", "mx.provider.example"]
	);
}

#[test]
fn a_recipient_no_longer_pending_holds_nothing() {
	let mut holds = Holds::default();
	let mut delivered = throttled(1300, 3, "mx.busy.example");
	delivered.status = RecipientStatus::Delivered;
	holds.add_envelope(&envelope(&[("a@busy.example", delivered)]));
	assert_eq!(holds.held(&Destination::new("busy.example"), 1000), None);
	assert_eq!(holds.deferrals(&Destination::new("busy.example")), 0);
}
