//! IMAP SORT command (RFC 5256).

use super::super::command::SortKey;
use super::helpers::{header_value, header_value_raw, load_content, search_matches};
use super::mailbox::{MessageRef, Snapshot};
use super::state::State;
use super::{Output, SearchKey, Session};
use crate::util::encoded_word;

/// A comparable SORT key value. Within one sort position every message yields
/// the same variant, so cross-variant comparison never happens in practice.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortValue {
	Num(u64),
	Text(String),
}

/// The sort value of a message for one key. `text` is the lowercased message
/// (headers + body), loaded only when a header-based key is present. SUBJECT
/// is treated specially: the decoded subject is computed from the RAW bytes
/// because lowercasing a B-encoded subject would mangle its base64 payload.
fn sort_value(
	key: SortKey,
	message: &MessageRef,
	snapshot: &Snapshot,
	text: Option<&str>,
) -> SortValue {
	let arrival = || {
		message
			.internal_date
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	};
	match key {
		SortKey::Arrival | SortKey::Date => SortValue::Num(arrival()),
		SortKey::Size => SortValue::Num(message.size),
		SortKey::From => SortValue::Text(header_field(text, "from")),
		SortKey::To => SortValue::Text(header_field(text, "to")),
		SortKey::Cc => SortValue::Text(header_field(text, "cc")),
		SortKey::Subject => SortValue::Text(normalized_subject_subject(snapshot, message)),
	}
}

/// A header value from the lowercased message text, or empty.
fn header_field(text: Option<&str>, name: &str) -> String {
	text.and_then(|t| header_value(t, name)).unwrap_or_default()
}

/// The Subject with a leading `re:`/`fwd:` run removed (RFC 5256 base subject,
/// simplified). Reads the raw message bytes so the RFC 2047 payload is
/// decoded before the `re:` strip: a subject stored as
/// `=?UTF-8?B?cmU6wqFIb2xhIQ==?=` collapses to `¡Hola!` and threads with
/// `=?UTF-8?Q?Re:_=C2=A1Hola!?=`.
fn normalized_subject_subject(snapshot: &Snapshot, message: &MessageRef) -> String {
	let raw = snapshot.read(message).unwrap_or_default();
	let text = String::from_utf8_lossy(&raw);
	let subject = header_value_raw(&text, "subject").unwrap_or_default();
	let mut subject = encoded_word::decode(&subject);
	loop {
		let trimmed = subject.trim_start();
		let lowered = trimmed.to_ascii_lowercase();
		let stripped = lowered
			.strip_prefix("re:")
			.or_else(|| lowered.strip_prefix("fwd:"))
			.or_else(|| lowered.strip_prefix("fw:"));
		match stripped {
			Some(rest) => subject = rest.to_string(),
			None => return lowered,
		}
	}
}

impl Session {
	pub(super) fn sort(
		&mut self,
		tag: &str,
		keys: &[(bool, SortKey)],
		criteria: &[SearchKey],
		uid: bool,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let needs_text = keys
			.iter()
			.any(|(_, key)| matches!(key, SortKey::From | SortKey::To | SortKey::Cc));

		// Collect matching messages with their sort values.
		let mut items: Vec<(Vec<SortValue>, u32, u32)> = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content, &[]));
			if !matches {
				continue;
			}
			let text = needs_text.then(|| load_content(snapshot, message));
			let values = keys
				.iter()
				.map(|(_, key)| sort_value(*key, message, snapshot, text.as_deref()))
				.collect();
			items.push((values, seqno, message.uid));
		}

		// Multi-key stable sort, honouring each key's REVERSE flag.
		items.sort_by(|a, b| {
			for (index, (reverse, _)) in keys.iter().enumerate() {
				let ordering = a.0[index].cmp(&b.0[index]);
				let ordering = if *reverse {
					ordering.reverse()
				} else {
					ordering
				};
				if ordering != std::cmp::Ordering::Equal {
					return ordering;
				}
			}
			a.1.cmp(&b.1)
		});

		let mut response = String::from("* SORT");
		for (_, seqno, message_uid) in &items {
			response.push_str(&format!(" {}", if uid { *message_uid } else { *seqno }));
		}
		response.push_str(&format!("\r\n{tag} OK SORT completed\r\n"));
		Output::text(response)
	}
}
