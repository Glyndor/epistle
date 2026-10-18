//! BDAT chunked message data (RFC 3030 CHUNKING): `BDAT <size> [LAST]` replaces
//! the dot-terminated DATA stream with length-prefixed binary chunks.

use super::super::line::MAX_LINE_LENGTH;
use super::super::reply::Reply;
use super::super::trace::line_error_reply;
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
		// Nothing is claimed for the announced size: the octets are charged
		// to the budget as they arrive (`reserve_chunk`), so a client that
		// announces a large chunk and drips it holds only what it sent.
		self.chunk_reservation = Reservation::none();
		Action::CollectChunk { size, last }
	}

	/// Charge `bytes` more octets of the chunk being read to the memory
	/// budget, before the network layer keeps them. `false` when the budget
	/// or the client's share has no room: the caller then answers
	/// [`Self::refuse_chunk`] and reads the rest of the chunk away.
	pub fn reserve_chunk(&mut self, bytes: usize) -> bool {
		let Some(budget) = &self.memory_budget else {
			return true;
		};
		self.chunk_reservation
			.try_grow(budget, self.peer_ip, bytes as u64)
			.is_ok()
	}

	/// End the transaction whose chunk did not fit the memory budget: the
	/// body and the part of the chunk already charged go back with it.
	pub fn refuse_chunk(&mut self) -> Action {
		self.reset();
		Action::Continue(budget_refusal())
	}

	/// Feed one BDAT chunk's raw bytes (already read by the network layer).
	/// Outside a recipient-bearing transaction the bytes are discarded and the
	/// command rejected. On the `LAST` chunk the message is finalized.
	pub fn bdat_chunk(&mut self, data: &[u8], last: bool) -> Action {
		let over;
		let finalize;
		// Octets the network layer did not charge while reading (a caller
		// that hands the chunk over whole) are charged here.
		let uncharged = data
			.len()
			.saturating_sub(usize::try_from(self.chunk_reservation.bytes()).unwrap_or(usize::MAX));
		if uncharged > 0
			&& matches!(self.state, State::ReceivingData { .. })
			&& !self.reserve_chunk(uncharged)
		{
			return self.refuse_chunk();
		}
		let chunk = std::mem::take(&mut self.chunk_reservation);
		{
			let State::ReceivingData {
				size,
				body,
				chunking,
				line_check,
				reserved,
				..
			} = &mut self.state
			else {
				// BDAT outside a transaction: octets already read are discarded.
				self.reset();
				return Action::Continue(Reply::bad_sequence());
			};
			*chunking = true;
			// The same framing DATA gets from the line decoder: no bare CR or
			// LF, no NUL, no line past the SMTP limit, whichever way the
			// octets are cut into chunks. A violation ends the connection as
			// it does in DATA; this chunk is already off the wire, so nothing
			// of it can be read as a command.
			let framing = line_check
				.feed(data, MAX_LINE_LENGTH)
				.and_then(|()| if last { line_check.finish() } else { Ok(()) });
			if let Err(error) = framing {
				self.reset();
				return Action::Close(line_error_reply(&error));
			}
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
		} = &mut self.state
		else {
			unreachable!("state checked above");
		};
		let running_size = *size;
		// The body moves into the message; `finalise` drops the state.
		let message = AcceptedMessage {
			reverse_path: reverse_path.clone(),
			recipients: recipients.clone(),
			no_dsn: no_dsn.clone(),
			data: std::mem::take(body),
			require_tls: *require_tls,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
		};
		super::finalise::finalise(self, message, running_size)
	}
}

/// The reply to a chunk the memory budget has no room for.
fn budget_refusal() -> Reply {
	Reply::single(452, "4.3.1 insufficient system resources; try again later")
}
