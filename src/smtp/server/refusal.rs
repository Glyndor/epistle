//! The reference a final refusal carries (`[smtp] reject_reference`): a
//! short random identifier at the end of the reply text and the same one in
//! the log line of that refusal, so a sender can quote it and the operator
//! finds the line at once. It is drawn fresh for each refusal and is not
//! derived from the server, the client or the message, so it says nothing
//! about any of them.

use std::net::IpAddr;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::AsyncWrite;

use crate::smtp::reply::Reply;

use super::{Server, send};

/// Octets of randomness in a reference: six hex digits.
const REFERENCE_OCTETS: usize = 3;

/// Where in the conversation a reply is sent, which decides whether a
/// refusal in it carries a reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Site {
	/// A command that is not part of a transaction.
	Other,
	/// `MAIL`, `RCPT` or `DATA`: only a permanent refusal carries one.
	Command,
	/// The end of the message (the dot or a `BDAT`): any refusal does.
	AfterData,
}

impl Site {
	/// The site of the line a client sent, `in_data` when it is part of the
	/// message body being received.
	pub(super) fn of(in_data: bool, line: &[u8]) -> Self {
		if in_data {
			return Self::AfterData;
		}
		let verb = line
			.split(|byte| byte.is_ascii_whitespace())
			.next()
			.unwrap_or_default();
		if verb.eq_ignore_ascii_case(b"BDAT") {
			Self::AfterData
		} else if [&b"MAIL"[..], b"RCPT", b"DATA"]
			.iter()
			.any(|name| verb.eq_ignore_ascii_case(name))
		{
			Self::Command
		} else {
			Self::Other
		}
	}

	/// Whether a reply with `code` sent here is a refusal that carries a
	/// reference.
	fn wants(self, code: u16) -> bool {
		match self {
			Self::Other => false,
			Self::Command => code >= 500,
			Self::AfterData => code >= 400,
		}
	}
}

/// A fresh reference: six lowercase hex digits from the system random
/// source. A server that cannot draw them has no reference to give, and
/// the refusal goes out without one.
fn new_reference() -> Option<String> {
	let mut octets = [0u8; REFERENCE_OCTETS];
	SystemRandom::new().fill(&mut octets).ok()?;
	Some(octets.iter().map(|octet| format!("{octet:02x}")).collect())
}

impl Server {
	/// `reply` with a reference when it is a refusal at `site` and the
	/// reference is on, and the log line of the refusal carrying the same
	/// one. Any other reply is returned as it came.
	pub(super) fn with_refusal_reference(
		&self,
		reply: Reply,
		site: Site,
		peer: Option<IpAddr>,
	) -> Reply {
		if !self.refusal_reference || !site.wants(reply.code()) {
			return reply;
		}
		let Some(reference) = new_reference() else {
			return reply;
		};
		let ip = peer.map(|ip| ip.to_string()).unwrap_or_default();
		tracing::info!(
			reference = %reference,
			code = reply.code(),
			%ip,
			reply = %reply.text(),
			"refusing message"
		);
		reply.with_reference(&reference)
	}

	/// Send `reply` at the end of a message: a refusal carries its
	/// reference, a reply that accepts goes as it is.
	pub(super) async fn refuse<W>(
		&self,
		peer: Option<IpAddr>,
		writer: &mut W,
		reply: &Reply,
	) -> std::io::Result<()>
	where
		W: AsyncWrite + Unpin + ?Sized,
	{
		let reply = self.with_refusal_reference(reply.clone(), Site::AfterData, peer);
		send(writer, &reply).await
	}
}
