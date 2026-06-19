//! BDAT chunked message data (RFC 3030 CHUNKING): `BDAT <size> [LAST]` replaces
//! the dot-terminated DATA stream with length-prefixed binary chunks.

use super::super::reply::Reply;
use super::types::{AcceptedMessage, State};
use super::{Action, MAX_MESSAGE_SIZE, Session};

impl Session {
	/// `BDAT <size> [LAST]` (RFC 3030). The declared octets are always read off
	/// the wire — even in a bad state — so they are consumed (and, if invalid,
	/// discarded by `bdat_chunk`) rather than parsed as commands; replying
	/// without consuming them would be a command-injection/desync vector.
	pub(super) fn bdat(&mut self, size: usize, last: bool) -> Action {
		// A single chunk over the ceiling can't be accepted, and draining it
		// would be a DoS, so abort the connection instead of reading it.
		if size > MAX_MESSAGE_SIZE {
			self.reset();
			return Action::Close(Reply::single(552, "5.3.4 message exceeds maximum size"));
		}
		Action::CollectChunk { size, last }
	}

	/// Feed one BDAT chunk's raw bytes (already read by the network layer).
	/// Outside a recipient-bearing transaction the bytes are discarded and the
	/// command rejected. On the `LAST` chunk the message is finalized.
	pub fn bdat_chunk(&mut self, data: &[u8], last: bool) -> Action {
		let over;
		let finalize;
		{
			let State::ReceivingData {
				size,
				body,
				chunking,
				..
			} = &mut self.state
			else {
				// BDAT outside a transaction: octets already read are discarded.
				self.reset();
				return Action::Continue(Reply::bad_sequence());
			};
			*chunking = true;
			*size += data.len();
			over = *size > MAX_MESSAGE_SIZE;
			if !over {
				body.extend_from_slice(data);
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
		};
		self.state = State::Greeted;
		Action::Deliver(Reply::ok(), message)
	}
}
