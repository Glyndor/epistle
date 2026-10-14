//! BDAT chunked message data (RFC 3030 CHUNKING): `BDAT <size> [LAST]` replaces
//! the dot-terminated DATA stream with length-prefixed binary chunks.

use super::super::reply::Reply;
use super::types::{AcceptedMessage, State};
use super::{Action, Session};
use crate::smtp::memory_budget::Reservation;

impl Session {
	/// `BDAT <size> [LAST]` (RFC 3030). The declared octets are always read off
	/// the wire, even in a bad state or when the chunk is refused, so they are
	/// consumed (a refused chunk is read and thrown away) rather than parsed
	/// as commands; replying without consuming them would be a
	/// command-injection/desync vector.
	pub(super) fn bdat(&mut self, size: usize, last: bool) -> Action {
		// A single chunk over the per-instance ceiling can't be accepted, and
		// draining it would be a DoS, so abort the connection instead of
		// reading it.
		if size > self.max_message_size {
			self.reset();
			return Action::Close(Reply::single(552, "5.3.4 message exceeds maximum size"));
		}
		// Outside a transaction the chunk is read and thrown away, so it is
		// neither held in memory nor charged to the budget.
		if !matches!(self.state, State::ReceivingData { .. }) {
			self.reset();
			return Action::DiscardChunk {
				size,
				reply: Reply::bad_sequence(),
			};
		}
		// Claim the chunk from the shared memory budget before it is read.
		// The claim waits in `chunk_reservation` until `bdat_chunk` adds it
		// to the body; a client that never sends the chunk drops it with
		// the session. A refused chunk is still consumed, without being
		// kept, so its octets are never parsed as commands.
		let mut chunk = Reservation::none();
		if let Some(budget) = &self.memory_budget
			&& chunk.try_grow(budget, size as u64).is_err()
		{
			self.reset();
			return Action::DiscardChunk {
				size,
				reply: Reply::single(452, "4.3.1 insufficient system resources; try again later"),
			};
		}
		self.chunk_reservation = chunk;
		Action::CollectChunk { size, last }
	}

	/// Feed one BDAT chunk's raw bytes (already read by the network layer).
	/// Outside a recipient-bearing transaction the bytes are discarded and the
	/// command rejected. On the `LAST` chunk the message is finalized.
	pub fn bdat_chunk(&mut self, data: &[u8], last: bool) -> Action {
		let over;
		let finalize;
		let chunk = std::mem::take(&mut self.chunk_reservation);
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
				self.reset();
				return Action::Continue(Reply::bad_sequence());
			};
			*chunking = true;
			*size += data.len();
			over = *size > self.max_message_size;
			if !over {
				body.extend_from_slice(data);
				reserved.absorb(chunk);
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
