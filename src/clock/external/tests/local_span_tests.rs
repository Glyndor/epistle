//! Tests for the span the adapter accepts as a measurement.
//!
//! The exchange is stamped twice, with the wall clock and with the monotonic
//! clock. Every case here is a pair of those stamps, so the shapes a real step
//! takes are exercised without moving the clock of the host.

use std::time::{Duration, Instant, SystemTime};

use crate::clock::external::adapter::{Edge, ProbeError, local_span};

/// One exchange: the wall clock advanced by `wall`, and `elapsed` really passed
/// between the two stamps. The two disagreeing is what a step looks like.
fn exchange(wall: Duration, elapsed: Duration) -> Result<f64, ProbeError> {
	let sent = Edge {
		wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
		monotonic: Instant::now(),
	};
	let received = Edge {
		wall: sent.wall + wall,
		monotonic: sent.monotonic + elapsed,
	};
	local_span(sent, received)
}

/// The wall clock is what the offset is built from, so both clocks have to agree
/// that the exchange happened. A step of a second and a half during a round-trip
/// of a second and three quarters leaves the wall clock advancing a fraction of
/// the time that really passed: the span stays positive and small, and only the
/// monotonic reading gives the step away. Reading that as a measurement reports
/// an offset the host clock never had.
#[test]
fn a_step_backwards_hidden_by_the_round_trip_is_not_a_measurement() {
	assert!(
		matches!(
			exchange(Duration::from_millis(300), Duration::from_millis(1_750)),
			Err(ProbeError::LocalJump)
		),
		"a wall clock that advanced 300 ms while 1750 ms really passed must be refused"
	);
}

/// A source that answers slowly is not a clock that jumped: the round-trip is
/// long and both clocks measured it, so the reading stays a measurement. The
/// span handed back is the wall clock one, which is what the delay is built from.
#[test]
fn a_long_round_trip_without_a_step_still_is_a_measurement() {
	let span = exchange(Duration::from_millis(900), Duration::from_millis(900))
		.expect("a slow but honest exchange");
	assert!(
		(span - 0.9).abs() < 1e-6,
		"the wall clock span is what the delay is built from: {span}"
	);
	assert!(
		exchange(Duration::from_millis(10), Duration::from_millis(10)).is_ok(),
		"an ordinary exchange must be accepted"
	);
}

/// The same step forwards: the wall clock runs ahead of the time that passed and
/// the span reads as a network delay nobody has to pay. The skew check refuses
/// it, including a step small enough to sit under the one second quality limit,
/// which the quality limit alone cannot see.
#[test]
fn a_step_forwards_is_not_a_measurement_however_small_the_step_is() {
	assert!(
		matches!(
			exchange(Duration::from_millis(900), Duration::from_millis(400)),
			Err(ProbeError::LocalJump)
		),
		"a wall clock that ran 500 ms ahead of the exchange must be refused even under the quality limit"
	);
	assert!(
		matches!(
			exchange(Duration::from_millis(1_100), Duration::from_millis(1_100)),
			Err(ProbeError::LocalJump)
		),
		"an exchange past the one second quality limit is refused"
	);
}

/// A backward step leaves `duration_since` with nothing to return, which is the
/// same failure as a forward step and is reported rather than read as a
/// zero-length exchange and a clean offset.
#[test]
fn a_step_backwards_is_not_a_zero_length_exchange() {
	let sent = Edge {
		wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
		monotonic: Instant::now(),
	};
	let received = Edge {
		wall: sent.wall - Duration::from_secs(1),
		monotonic: sent.monotonic + Duration::from_millis(10),
	};
	assert!(
		matches!(local_span(sent, received), Err(ProbeError::LocalJump)),
		"a wall clock that went backwards must not be read as a zero-length exchange"
	);
}
