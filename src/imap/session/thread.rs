//! IMAP THREAD command, ORDEREDSUBJECT algorithm (RFC 5256 §3).

use super::base_subject::base_subject;
use super::helpers::{header_value_raw, search_matches};
use super::sort_keys::sent_seconds;
use super::state::State;
use super::{Output, SearchKey, Session};
use std::collections::HashMap;

/// One matching message: its sent date and sequence number, which order it,
/// and the number the reply shows (the UID for UID THREAD).
struct Member {
	sent: i64,
	seqno: u32,
	id: u32,
}

impl Session {
	pub(super) fn thread(&mut self, tag: &str, criteria: &[SearchKey], uid: bool) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = snapshot.max_identifier(false);
		let maxima = (total, snapshot.max_identifier(true));
		let mut groups: HashMap<String, Vec<Member>> = HashMap::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let is_match = criteria.iter().all(|key| {
				search_matches(key, message, seqno, maxima, snapshot, &mut content, &[])
			});
			if !is_match {
				continue;
			}
			let raw = snapshot.read(message).unwrap_or_default();
			let text = String::from_utf8_lossy(&raw);
			let subject = base_subject(&header_value_raw(&text, "subject").unwrap_or_default());
			groups.entry(subject).or_default().push(Member {
				sent: sent_seconds(&text, message),
				seqno,
				id: if uid { message.uid } else { seqno },
			});
		}

		let mut response = String::from("* THREAD ");
		for thread in ordered_threads(groups) {
			response.push_str(&render(&thread));
		}
		response.push_str(&format!("\r\n{tag} OK THREAD completed\r\n"));
		Output::text(response)
	}
}

/// Sort each base-subject group by sent date, then the groups by the sent
/// date of their first message. Equal dates fall back to the sequence
/// number, as everywhere in RFC 5256.
fn ordered_threads(groups: HashMap<String, Vec<Member>>) -> Vec<Vec<Member>> {
	let mut threads: Vec<Vec<Member>> = groups
		.into_values()
		.map(|mut members| {
			members.sort_by_key(|member| (member.sent, member.seqno));
			members
		})
		.collect();
	threads.sort_by_key(|members| {
		members
			.first()
			.map(|first| (first.sent, first.seqno))
			.unwrap_or_default()
	});
	threads
}

/// One thread in the THREAD reply: the first message is the parent and every
/// other message is its child. A lone child continues the parent's list,
/// while several children are each a nested list: `(1)`, `(1 2)`,
/// `(1 (2)(3))`.
fn render(members: &[Member]) -> String {
	let ids: Vec<String> = members.iter().map(|member| member.id.to_string()).collect();
	match ids.as_slice() {
		[] => String::new(),
		[parent] => format!("({parent})"),
		[parent, child] => format!("({parent} {child})"),
		[parent, children @ ..] => {
			let children: String = children.iter().map(|child| format!("({child})")).collect();
			format!("({parent} {children})")
		}
	}
}
