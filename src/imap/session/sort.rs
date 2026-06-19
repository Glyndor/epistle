//! IMAP SORT command (RFC 5256).

use super::super::command::SortKey;
use super::helpers::{header_value, load_content, search_matches};
use super::mailbox::MessageRef;
use super::{Output, SearchKey, Session, State};

/// A comparable SORT key value. Within one sort position every message yields
/// the same variant, so cross-variant comparison never happens in practice.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortValue {
	Num(u64),
	Text(String),
}

/// The sort value of a message for one key. `text` is the lowercased message
/// (headers + body), loaded only when a header-based key is present.
fn sort_value(key: SortKey, message: &MessageRef, text: Option<&str>) -> SortValue {
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
		SortKey::Subject => SortValue::Text(normalized_subject(text)),
	}
}

/// A header value from the lowercased message text, or empty.
fn header_field(text: Option<&str>, name: &str) -> String {
	text.and_then(|t| header_value(t, name)).unwrap_or_default()
}

/// The Subject with a leading `re:`/`fwd:` run removed (RFC 5256 base subject,
/// simplified).
fn normalized_subject(text: Option<&str>) -> String {
	let mut subject = header_field(text, "subject");
	loop {
		let trimmed = subject.trim_start();
		let stripped = trimmed
			.strip_prefix("re:")
			.or_else(|| trimmed.strip_prefix("fwd:"))
			.or_else(|| trimmed.strip_prefix("fw:"));
		match stripped {
			Some(rest) => subject = rest.to_string(),
			None => return trimmed.to_string(),
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
		let needs_headers = keys.iter().any(|(_, key)| {
			matches!(
				key,
				SortKey::From | SortKey::To | SortKey::Cc | SortKey::Subject | SortKey::Date
			)
		});

		// Collect matching messages with their sort values.
		let mut items: Vec<(Vec<SortValue>, u32, u32)> = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content));
			if !matches {
				continue;
			}
			let text = needs_headers.then(|| load_content(snapshot, message));
			let values = keys
				.iter()
				.map(|(_, key)| sort_value(*key, message, text.as_deref()))
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
