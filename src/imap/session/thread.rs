//! IMAP THREAD command, ORDEREDSUBJECT algorithm (RFC 5256).

use super::helpers::{header_value, load_content, search_matches};
use super::{Output, SearchKey, Session, State};

impl Session {
	pub(super) fn thread(&mut self, tag: &str, criteria: &[SearchKey], uid: bool) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		// (base subject, arrival secs, output id) for each matching message.
		let mut matched: Vec<(String, u64, u32)> = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let is_match = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content));
			if !is_match {
				continue;
			}
			let text = load_content(snapshot, message);
			let subject = base_subject(&text);
			let arrival = message
				.internal_date
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			matched.push((subject, arrival, if uid { message.uid } else { seqno }));
		}

		let threads = group_by_subject(matched);

		let mut response = String::from("* THREAD ");
		for thread in &threads {
			response.push('(');
			let members: Vec<String> = thread.iter().map(|id| id.to_string()).collect();
			response.push_str(&members.join(" "));
			response.push(')');
		}
		response.push_str(&format!("\r\n{tag} OK THREAD completed\r\n"));
		Output::text(response)
	}
}

/// The Subject header with a leading `re:`/`fwd:` run removed (the base subject
/// used to group a thread).
fn base_subject(text: &str) -> String {
	let mut subject = header_value(text, "subject").unwrap_or_default();
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

/// Group messages sharing a base subject into threads, ordering members and
/// threads by arrival time (RFC 5256 ORDEREDSUBJECT).
fn group_by_subject(mut matched: Vec<(String, u64, u32)>) -> Vec<Vec<u32>> {
	use std::collections::BTreeMap;
	// subject → members sorted by arrival.
	let mut groups: BTreeMap<String, Vec<(u64, u32)>> = BTreeMap::new();
	matched.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
	for (subject, arrival, id) in matched {
		groups.entry(subject).or_default().push((arrival, id));
	}
	// Order threads by their earliest member's arrival.
	let mut threads: Vec<(u64, Vec<u32>)> = groups
		.into_values()
		.map(|members| {
			let first = members.first().map(|(arrival, _)| *arrival).unwrap_or(0);
			(first, members.into_iter().map(|(_, id)| id).collect())
		})
		.collect();
	threads.sort_by_key(|(first, _)| *first);
	threads.into_iter().map(|(_, members)| members).collect()
}
