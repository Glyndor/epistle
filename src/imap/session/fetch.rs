//! IMAP FETCH response generation and Seen transitions.

use super::super::command::{FetchSection, SectionKind, SequenceSet};
use super::helpers::format_internaldate;
use super::mailbox::{Flag, render_flags};
use super::state::State;
use super::{FetchItem, Output, Session};

impl Session {
	pub(super) fn fetch(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		items: &[FetchItem],
		uid: bool,
		changed_since: Option<u64>,
		vanished: bool,
	) -> Output {
		let uidonly = self.uidonly;
		// Capture the SEARCHRES `$` set before the immutable borrow of
		// `self.state`. The set is keyed by UID; the resolver maps through
		// the snapshot to current seqnos (non-UID) or returns UIDs directly
		// (UID commands). Expunged messages drop out automatically per
		// RFC 5182 §2.1.
		let saved_search = self.saved_search.clone();
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		let saved = match saved_search.as_ref() {
			Some(saved) if saved.are_uids == uid => {
				if uid {
					saved.uids.clone()
				} else {
					saved
						.uids
						.iter()
						.filter_map(|u| snapshot.sequence_of_uid(*u))
						.collect()
				}
			}
			_ => Vec::new(),
		};

		let total = snapshot.max_identifier(false);
		let maximum = snapshot.max_identifier(uid);
		let mut bytes = Vec::new();
		// QRESYNC VANISHED: report UIDs expunged since CHANGEDSINCE before FETCHes.
		if let (true, Some(since)) = (vanished, changed_since) {
			let uids = snapshot.vanished_since(since);
			if !uids.is_empty() {
				let line = format!("* VANISHED (EARLIER) {}\r\n", super::codes::uid_set(&uids));
				bytes.extend_from_slice(line.as_bytes());
			}
		}
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, maximum, &saved) {
				continue;
			}
			// CONDSTORE CHANGEDSINCE: skip messages not changed since `n`.
			if changed_since.is_some_and(|since| message.modseq <= since) {
				continue;
			}

			let seen_changed =
				!*read_only && items.iter().any(sets_seen) && !message.flags.contains(&Flag::Seen);
			if seen_changed {
				let mut flags = message.flags.clone();
				flags.push(Flag::Seen);
				if snapshot.store_flags(sequence_number, flags).is_err() {
					return Output::text(format!("{tag} NO cannot store flags\r\n"));
				}
			}
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let needs_data =
				items.iter().any(|item| {
					matches!(
						item,
						FetchItem::Preview
							| FetchItem::Body | FetchItem::Binary
							| FetchItem::BinarySize
							| FetchItem::Envelope | FetchItem::Structure { .. }
							| FetchItem::Section(_)
							| FetchItem::Rfc822 | FetchItem::Rfc822Header
							| FetchItem::Rfc822Text
					)
				});
			let data = if needs_data {
				match snapshot.read(message) {
					Ok(data) => data,
					Err(_) => return Output::text(format!("{tag} NO message unavailable\r\n")),
				}
			} else {
				Vec::new()
			};
			let parsed = needs_data.then(|| crate::imap::fetch::parse(&data));

			let mut parts: Vec<Vec<u8>> = Vec::new();
			for item in items {
				match item {
					// UIDONLY: the UID leads the UIDFETCH response, so the
					// redundant UID data item is omitted (RFC 9586).
					FetchItem::Uid if uidonly => {}
					FetchItem::Flags => {
						parts.push(format!("FLAGS {}", render_flags(&message.flags)).into_bytes());
					}
					FetchItem::Uid => {
						parts.push(format!("UID {}", message.uid).into_bytes());
					}
					FetchItem::Rfc822Size => {
						parts.push(format!("RFC822.SIZE {}", message.size).into_bytes());
					}
					FetchItem::InternalDate => {
						let dt = format_internaldate(message.internal_date);
						parts.push(format!("INTERNALDATE \"{dt}\"").into_bytes());
					}
					FetchItem::ModSeq => {
						parts.push(format!("MODSEQ ({})", message.modseq).into_bytes());
					}
					// OBJECTID (RFC 8474): the stable message UUID; each message is
					// its own singleton thread, so THREADID equals EMAILID.
					FetchItem::EmailId => {
						parts.push(format!("EMAILID ({})", message.id()).into_bytes());
					}
					FetchItem::ThreadId => {
						parts.push(format!("THREADID ({})", message.id()).into_bytes());
					}
					// SAVEDATE (RFC 8514): mailbox save time (the file mtime).
					FetchItem::SaveDate => {
						let dt = format_internaldate(message.internal_date);
						parts.push(format!("SAVEDATE \"{dt}\"").into_bytes());
					}
					FetchItem::Preview => {
						parts.push(format!("PREVIEW \"{}\"", preview_text(&data)).into_bytes())
					}
					_ => {
						if let Some(parsed) = &parsed {
							match data_item(item, parsed, &data) {
								Ok(part) => parts.push(part),
								Err(()) => {
									return Output::text(format!(
										"{tag} NO [UNKNOWN-CTE] cannot decode body section\r\n"
									));
								}
							}
						}
					}
				}
			}

			if seen_changed && !items.contains(&FetchItem::Flags) {
				parts.push(format!("FLAGS {}", render_flags(&message.flags)).into_bytes());
			}

			let header = if uidonly {
				format!("* UIDFETCH {} (", message.uid)
			} else {
				format!("* {sequence_number} FETCH (")
			};
			bytes.extend_from_slice(header.as_bytes());
			for (index, part) in parts.iter().enumerate() {
				if index > 0 {
					bytes.push(b' ');
				}
				bytes.extend_from_slice(part);
			}
			bytes.extend_from_slice(b")\r\n");
		}
		bytes.extend_from_slice(format!("{tag} OK FETCH completed\r\n").as_bytes());
		Output {
			bytes,
			close: false,
			collect_literal: None,
			discard_literal: None,
			idle: false,
			upgrade_tls: false,
			compress: false,
			collect_auth: false,
		}
	}
}

fn sets_seen(item: &FetchItem) -> bool {
	matches!(
		item,
		FetchItem::Body | FetchItem::Binary | FetchItem::Rfc822 | FetchItem::Rfc822Text
	) || matches!(item, FetchItem::Section(section) if !section.peek && !section.size)
}

fn data_item(
	item: &FetchItem,
	parsed: &mail_parser::Message<'_>,
	raw: &[u8],
) -> Result<Vec<u8>, ()> {
	use crate::imap::fetch::{bodystructure, envelope, section};
	match item {
		FetchItem::Envelope => {
			let mut out = b"ENVELOPE ".to_vec();
			out.extend(envelope::render(parsed, 0));
			Ok(out)
		}
		FetchItem::Structure { extensions } => {
			let mut out = if *extensions {
				b"BODYSTRUCTURE ".to_vec()
			} else {
				b"BODY ".to_vec()
			};
			out.extend(bodystructure::render(parsed, 0, *extensions));
			Ok(out)
		}
		FetchItem::Body | FetchItem::Rfc822 => {
			let label = if matches!(item, FetchItem::Rfc822) {
				"RFC822"
			} else {
				"BODY[]"
			};
			let mut out = format!("{label} {{{}}}\r\n", raw.len()).into_bytes();
			out.extend_from_slice(raw);
			Ok(out)
		}
		FetchItem::Rfc822Header | FetchItem::Rfc822Text => {
			let header = matches!(item, FetchItem::Rfc822Header);
			section::render_label(
				parsed,
				&FetchSection {
					path: Vec::new(),
					kind: if header {
						SectionKind::Header
					} else {
						SectionKind::Text
					},
					partial: None,
					peek: header,
					binary: false,
					size: false,
				},
				if header {
					"RFC822.HEADER"
				} else {
					"RFC822.TEXT"
				},
			)
		}
		FetchItem::Section(value) => section::render(parsed, value),
		FetchItem::Binary | FetchItem::BinarySize => section::render(
			parsed,
			&FetchSection {
				path: Vec::new(),
				kind: SectionKind::Entire,
				partial: None,
				peek: false,
				binary: true,
				size: matches!(item, FetchItem::BinarySize),
			},
		),
		_ => unreachable!("metadata items are rendered without message content"),
	}
}

/// Maximum characters in a PREVIEW snippet (RFC 8970 recommends ~200).
const PREVIEW_LEN: usize = 200;

/// Build a short PREVIEW snippet (RFC 8970) from a raw message: take the body
/// after the header block, collapse whitespace, and truncate. Quotes and
/// backslashes are escaped so the result is a valid IMAP quoted string.
fn preview_text(raw: &[u8]) -> String {
	let text = String::from_utf8_lossy(raw);
	// The body starts after the first blank line (CRLF or LF).
	let body = text
		.split_once("\r\n\r\n")
		.or_else(|| text.split_once("\n\n"))
		.map(|(_, body)| body)
		.unwrap_or(&text);

	let mut preview = String::with_capacity(PREVIEW_LEN);
	let mut last_was_space = false;
	for ch in body.chars() {
		if preview.chars().count() >= PREVIEW_LEN {
			break;
		}
		if ch.is_whitespace() {
			if !last_was_space && !preview.is_empty() {
				preview.push(' ');
				last_was_space = true;
			}
		} else if ch == '"' || ch == '\\' {
			preview.push('\\');
			preview.push(ch);
			last_was_space = false;
		} else if !ch.is_control() {
			preview.push(ch);
			last_was_space = false;
		}
	}
	preview.trim_end().to_string()
}
