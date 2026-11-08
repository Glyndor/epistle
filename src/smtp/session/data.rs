//! `DATA`: the dot-terminated message stream.

use super::types::State;
use super::{Action, Reply, Reservation, Session, finalise};

impl Session {
	pub(super) fn data(&mut self) -> Action {
		match &self.state {
			// DATA and BDAT are mutually exclusive (RFC 3030): refuse DATA once a
			// BDAT chunk has begun, or after any data has been collected.
			State::ReceivingData { body, chunking, .. } if body.is_empty() && !*chunking => {
				Action::CollectData(Reply::start_mail_input())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	/// Feed one data line (CRLF already stripped and enforced upstream).
	/// Returns `None` while more lines are expected.
	pub fn data_line(&mut self, line: &[u8]) -> Option<Action> {
		if line == b"." {
			return Some(finalise::finalise_from_state(self));
		}
		// Dot-unstuffing (RFC 5321 section 4.5.2).
		let State::ReceivingData {
			size,
			body,
			reserved,
			budget_exhausted,
			..
		} = &mut self.state
		else {
			self.reset();
			return Some(Action::Continue(Reply::bad_sequence()));
		};
		let content = line.strip_prefix(b".").unwrap_or(line);
		let delta = content.len() + 2;
		*size += delta;
		if *size > self.max_message_size {
			// Keep the size counter for the final 552 reply, but don't
			// extend the body past the cap.
			return None;
		}
		// Memory-budget reservation: claim the line's bytes, or stop
		// growing the body and flag the message as over-budget. The claim
		// lives in the state and goes back when the state is dropped; the
		// body and the counter stay consistent because we never extend
		// past a failed reservation.
		if let Some(budget) = &self.memory_budget
			&& reserved
				.try_grow(budget, self.peer_ip, delta as u64)
				.is_err()
		{
			*budget_exhausted = true;
			return None;
		}
		body.extend_from_slice(content);
		body.extend_from_slice(b"\r\n");
		None
	}

	/// The budget claim of the body accepted last, for the connection loop
	/// to hold until that body's delivery is over.
	pub fn take_delivery_reservation(&mut self) -> Reservation {
		std::mem::take(&mut self.delivery_reservation)
	}
}
