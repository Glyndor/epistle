//! The trace fields final delivery adds to the copy it stores, and the
//! forwarding loop they reveal.
//!
//! RFC 5321 section 4.4: the system that makes final delivery inserts
//! `Return-Path` with the reverse-path of the transaction at the top of the
//! message, `<>` for the null sender. A relay must not add one, so whatever
//! `Return-Path` a message arrives with was written by someone else and is
//! not trusted: it is removed before ours goes on, and every stored copy
//! carries exactly one.
//!
//! `Delivered-To` names the address a copy was finally delivered to (an
//! alias member's own address, after expansion), once per mailbox delivery.
//! Copies forwarded onward carry it too, which is what makes a loop
//! visible: a message that comes back already naming the address it is
//! about to be forwarded from again has been here before. Earlier
//! `Delivered-To` fields are kept for exactly that reason.

use crate::smtp::trace::{header_values, strip_headers};

/// A forward the delivery asks the caller to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
	/// Where the copy goes.
	pub to: String,
	/// The address whose delivery forwarded it, for the copy's
	/// `Delivered-To`.
	pub delivered_to: String,
}

/// The copy of `data` that lands in the mailbox of `delivered_to`, for a
/// message whose envelope sender was `reverse_path`.
pub(super) fn final_copy(reverse_path: &str, delivered_to: &str, data: &[u8]) -> Vec<u8> {
	let mut copy = format!(
		"Return-Path: <{}>\r\nDelivered-To: {}\r\n",
		one_line(reverse_path),
		one_line(delivered_to)
	)
	.into_bytes();
	copy.extend_from_slice(&strip_headers(data, &["return-path"]));
	copy
}

/// The copy of `data` that the delivery to `delivered_to` forwards onward.
pub(crate) fn forwarded_copy(delivered_to: &str, data: &[u8]) -> Vec<u8> {
	let mut copy = format!("Delivered-To: {}\r\n", one_line(delivered_to)).into_bytes();
	copy.extend_from_slice(data);
	copy
}

/// Whether `data` already names `address` in a `Delivered-To` field.
pub(super) fn already_delivered_to(data: &[u8], address: &str) -> bool {
	header_values(data, "delivered-to").iter().any(|value| {
		value
			.trim_matches(|c: char| c == '<' || c == '>' || c.is_whitespace())
			.eq_ignore_ascii_case(address)
	})
}

/// `text` without line breaks. The values come from the envelope and the
/// directory, already parsed; a line break would still start a field of
/// its own, so none survives.
fn one_line(text: &str) -> String {
	text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

/// `targets` as the redirects of the delivery to `delivered_to`.
pub(super) fn redirects(targets: Vec<String>, delivered_to: &str) -> Vec<Redirect> {
	targets
		.into_iter()
		.map(|to| Redirect {
			to,
			delivered_to: delivered_to.to_string(),
		})
		.collect()
}

/// The outcome of a delivery to `delivered_to` that would forward to
/// `targets` a message which already names that address in `Delivered-To`:
/// it has been through this delivery before, so it is refused (nothing
/// stored, nothing forwarded) for the caller to bounce with 5.4.6. `None`
/// when the delivery forwards nowhere or the message is new here. A plain
/// delivery is never refused on this ground alone: without a forward there
/// is no loop to break, and the `Received` hop limit still applies.
pub(super) fn forwarding_loop(
	message: &crate::smtp::session::AcceptedMessage,
	delivered_to: &str,
	targets: &[String],
) -> Option<super::Delivered> {
	if targets.is_empty() || !already_delivered_to(&message.data, delivered_to) {
		return None;
	}
	Some(super::Delivered {
		looped: vec![delivered_to.to_string()],
		..super::Delivered::default()
	})
}
