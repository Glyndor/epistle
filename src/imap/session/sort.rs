//! IMAP SORT command (RFC 5256).

use super::super::command::SortKey;
use super::base_subject::base_subject;
use super::helpers::{header_value_raw, search_matches};
use super::mailbox::MessageRef;
use super::sort_keys::{address_key, internal_seconds, sent_seconds};
use super::state::State;
use super::{Output, SearchKey, Session};

/// A comparable SORT key value. Within one sort position every message yields
/// the same variant, so cross-variant comparison never happens in practice.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortValue {
	Num(i64),
	Text(String),
}

/// The sort value of a message for one key. `text` is the message as read
/// from the store, loaded only when a key other than ARRIVAL or SIZE is
/// present.
fn sort_value(key: SortKey, message: &MessageRef, text: Option<&str>) -> SortValue {
	let text = text.unwrap_or_default();
	match key {
		SortKey::Arrival => SortValue::Num(internal_seconds(message)),
		SortKey::Date => SortValue::Num(sent_seconds(text, message)),
		SortKey::Size => SortValue::Num(i64::try_from(message.size).unwrap_or(i64::MAX)),
		SortKey::From => SortValue::Text(address_key(text, "from")),
		SortKey::To => SortValue::Text(address_key(text, "to")),
		SortKey::Cc => SortValue::Text(address_key(text, "cc")),
		SortKey::Subject => SortValue::Text(base_subject(
			&header_value_raw(text, "subject").unwrap_or_default(),
		)),
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

		let total = snapshot.max_identifier(false);
		let maxima = (total, snapshot.max_identifier(true));
		let needs_text = keys
			.iter()
			.any(|(_, key)| !matches!(key, SortKey::Arrival | SortKey::Size));

		// Collect matching messages with their sort values.
		let mut items: Vec<(Vec<SortValue>, u32, u32)> = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria.iter().all(|key| {
				search_matches(key, message, seqno, maxima, snapshot, &mut content, &[])
			});
			if !matches {
				continue;
			}
			let text = needs_text.then(|| {
				String::from_utf8_lossy(&snapshot.read(message).unwrap_or_default()).into_owned()
			});
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
