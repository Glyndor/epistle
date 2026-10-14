//! BDAT chunked message data (RFC 3030 CHUNKING): `BDAT <size> [LAST]` replaces
//! the dot-terminated DATA stream with length-prefixed binary chunks.

use super::super::reply::Reply;
use super::types::{AcceptedMessage, State};
use super::{Action, Session};

impl Session {
	/// `BDAT <size> [LAST]` (RFC 3030). The declared octets are always read off
	/// the wire — even in a bad state — so they are consumed (and, if invalid,
	/// discarded by `bdat_chunk`) rather than parsed as commands; replying
	/// without consuming them would be a command-injection/desync vector.
	pub(super) fn bdat(&mut self, size: usize, last: bool) -> Action {
		// A single chunk over the per-instance ceiling can't be accepted, and
		// draining it would be a DoS, so abort the connection instead of
		// reading it.
		if size > self.max_message_size {
			self.reset();
			return Action::Close(Reply::single(552, "5.3.4 message exceeds maximum size"));
		}
		// Try to claim the chunk from the shared memory budget up front:
		// the chunk arrives as a single contiguous allocation, so the
		// reservation must succeed before we ask the network layer to read
		// it. Failing here returns the same 452 the DATA path uses at end
		// of message; the difference is that the chunk is read off the
		// wire regardless, so the reply is delivered before any
		// subsequent command.
		if let Some(budget) = &self.memory_budget
			&& budget.try_reserve(size as u64).is_err()
		{
			self.reset();
			return Action::Continue(Reply::single(
				452,
				"4.3.1 insufficient system resources; try again later",
			));
		}
		Action::CollectChunk { size, last }
	}

	/// Feed one BDAT chunk's raw bytes (already read by the network layer).
	/// Outside a recipient-bearing transaction the bytes are discarded and the
	/// command rejected. On the `LAST` chunk the message is finalized.
	pub fn bdat_chunk(&mut self, data: &[u8], last: bool) -> Action {
		let over;
		let finalize;
		let reserved_delta = data.len() as u64;
		{
			let State::ReceivingData {
				size,
				body,
				chunking,
				reserved,
				..
			} = &mut self.state
			else {
				// BDAT outside a transaction: octets already read are discarded.
				// The up-front reservation in `bdat` is no longer owned by any
				// state, so release it here.
				if let Some(budget) = &self.memory_budget {
					budget.release(reserved_delta);
				}
				self.reset();
				return Action::Continue(Reply::bad_sequence());
			};
			*chunking = true;
			*size += data.len();
			over = *size > self.max_message_size;
			if !over {
				body.extend_from_slice(data);
				*reserved = reserved.saturating_add(reserved_delta);
			}
			finalize = last && !over;
		}
		// Reject as soon as the cumulative size crosses the ceiling (RFC 1870),
		// reading no further chunks.
		if over {
			self.reset();
			return Action::Continue(Reply::single(552, "5.3.4 message exceeds maximum size"));
		}
		if !finalize {
			return Action::Continue(Reply::single(250, "2.0.0 chunk received"));
		}
		let State::ReceivingData {
			reverse_path,
			recipients,
			no_dsn,
			size,
			body,
			require_tls,
			..
		} = &self.state
		else {
			unreachable!("state checked above");
		};
		let message = AcceptedMessage {
			reverse_path: reverse_path.clone(),
			recipients: recipients.clone(),
			no_dsn: no_dsn.clone(),
			data: body.clone(),
			require_tls: *require_tls,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
		};
		super::finalise::finalise(self, message, *size)
	}
}
