use super::*;

#[test]
fn a_state_round_trips_and_is_bound_to_its_type() {
	let state = State {
		kind: Kind::Email,
		epoch: 0x0123_4567_89ab_cdef,
		position: 42,
	};
	let wire = state.encode();
	assert_eq!(State::decode(&wire, Kind::Email), Some(state));
	assert_eq!(State::decode(&wire, Kind::Mailbox), None);
	assert_eq!(State::decode("0", Kind::Email), None);
	assert_eq!(State::decode(&wire[..wire.len() - 2], Kind::Email), None);
}
