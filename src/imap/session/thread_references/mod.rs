//! IMAP THREAD=REFERENCES (RFC 5256 §3).
//!
//! The steps follow the RFC: link every searched message to its references
//! ([`build`]), drop the dummies, order and merge the threads by base
//! subject ([`gather`]), and write the reply ([`render`]).
//!
//! The headers and the mailbox are client-controlled, since anyone can
//! APPEND or send mail with any References, so the cost is bounded by
//! construction rather than by caps on depth:
//!
//! - Each header is scanned once, and each message adds at most
//!   [`msgid::MAX_REFERENCES`] + 1 containers of constant size, whatever the
//!   length of its ids ([`msgid`]).
//! - The loop check of step 1 is a link-cut tree, amortized O(log n) per
//!   link however deep the chains are ([`forest`]).
//! - Every lookup is a hash map, every pass is linear over the containers,
//!   and the sorts are O(n log n).
//! - Nothing walks the tree recursively: the passes over it keep their
//!   pending work on heap stacks, so a reply chain as long as the mailbox
//!   cannot exhaust the thread's stack.

mod build;
mod forest;
mod gather;
mod msgid;
mod render;

use super::base_subject::base_subject_and_reply;
use super::helpers::{header_value_raw, search_matches};
use super::sort_keys::sent_seconds;
use super::state::State;
use super::{Output, SearchKey, Session};

/// What steps 4 to 6 and the reply need from a searched message.
struct Message {
	seqno: u32,
	uid: u32,
	/// The RFC 5256 §2.2 sent date, in seconds.
	sent: i64,
	/// The key of the base subject, `None` when it is empty.
	subject: Option<msgid::Key>,
	/// Whether the subject marks a reply or forward (RFC 5256 §3).
	reply: bool,
}

/// The threads after step 3. Nodes `0..messages` are the messages, in the
/// order they were added; any node after them is a dummy.
struct Tree {
	messages: usize,
	children: Vec<Vec<u32>>,
	roots: Vec<u32>,
}

impl Tree {
	fn new(messages: usize) -> Self {
		Self {
			messages,
			children: vec![Vec::new(); messages],
			roots: Vec::new(),
		}
	}

	fn is_dummy(&self, node: u32) -> bool {
		node as usize >= self.messages
	}

	/// Add a dummy over `members`, which are messages.
	fn dummy(&mut self, members: Vec<u32>) -> u32 {
		self.children.push(members);
		(self.children.len() - 1) as u32
	}

	/// The node itself, or the first child of a dummy.
	fn first_message(&self, node: u32) -> u32 {
		if self.is_dummy(node) {
			self.children[node as usize][0]
		} else {
			node
		}
	}
}

/// THREAD=REFERENCES over messages added in sequence order.
pub(super) struct Threader {
	builder: build::Builder,
	messages: Vec<Message>,
}

impl Threader {
	pub(super) fn new() -> Self {
		Self {
			builder: build::Builder::new(),
			messages: Vec::new(),
		}
	}

	/// Add the next searched message: its numbers, its sent date and its
	/// raw text, of which only the header block is read.
	pub(super) fn add(&mut self, seqno: u32, uid: u32, sent: i64, text: &str) {
		let header = |name| header_value_raw(text, name);
		let id = header("message-id").as_deref().and_then(msgid::first_id);
		let references = msgid::references(
			header("references").as_deref(),
			header("in-reply-to").as_deref(),
		);
		let (base, reply) = base_subject_and_reply(&header("subject").unwrap_or_default());
		let index = self.messages.len() as u32;
		self.builder.add(index, id, &references);
		self.messages.push(Message {
			seqno,
			uid,
			sent,
			subject: (!base.is_empty()).then(|| msgid::digest(base.as_bytes())),
			reply,
		});
	}

	/// Append the thread-lists to `out`, numbered by UID when `uid` is set.
	pub(super) fn render(self, uid: bool, out: &mut String) {
		let mut tree = self.builder.prune(self.messages.len());
		gather::gather(&mut tree, &self.messages);
		render::render(&tree, &self.messages, uid, out);
	}
}

impl Session {
	pub(super) fn thread_references(
		&mut self,
		tag: &str,
		criteria: &[SearchKey],
		uid: bool,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		let total = snapshot.max_identifier(false);
		let maxima = (total, snapshot.max_identifier(true));
		let mut threader = Threader::new();
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
			threader.add(seqno, message.uid, sent_seconds(&text, message), &text);
		}
		// RFC 5256 §4: `"THREAD" [SP 1*thread-list]`, so no space when
		// nothing matched.
		let mut response = String::from("* THREAD");
		let mut threads = String::new();
		threader.render(uid, &mut threads);
		if !threads.is_empty() {
			response.push(' ');
			response.push_str(&threads);
		}
		response.push_str(&format!("\r\n{tag} OK THREAD completed\r\n"));
		Output::text(response)
	}
}

#[cfg(test)]
#[path = "threader_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "threader_hostile_tests.rs"]
mod hostile_tests;
