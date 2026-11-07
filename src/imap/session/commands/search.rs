//! IMAP SEARCH, ESEARCH and MULTISEARCH command handlers (RFC 9051 §6.4.4,
//! RFC 4731, RFC 7377).

use super::super::super::command::{ReturnOpt, SearchScope};
use super::super::helpers::search_matches;
use super::super::mailbox::{self, Snapshot};
use super::super::state::State;
use super::super::{Output, SearchKey, Session};
use super::codes::{esearch_line, esearch_multi_line};

impl Session {
	pub(in crate::imap::session) fn search(
		&mut self,
		tag: &str,
		criteria: &[SearchKey],
		uid: bool,
		return_opts: Option<&[ReturnOpt]>,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = snapshot.max_identifier(false);
		let maxima = (total, snapshot.max_identifier(true));
		// SEARCH criteria never carry SEARCHRES `$` placeholders — only the
		// consuming commands (FETCH/STORE/COPY/UID EXPUNGE) do — so the saved
		// set is irrelevant here.
		let mut hits = Vec::new();
		// The SEARCHRES-saved set is always keyed by UID (RFC 5182 §2.1):
		// the saved entries must reference the same messages across
		// expunges, not the snapshot positions at SAVE time. Track UIDs
		// alongside the response-shaped `hits` (which is seqnos or UIDs
		// depending on `uid`) so the protocol reply and the resolver agree.
		let mut saved_uids = Vec::new();
		let mut modseqs = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria.iter().all(|key| {
				search_matches(key, message, seqno, maxima, snapshot, &mut content, &[])
			});
			if matches {
				hits.push(if uid { message.uid } else { seqno });
				saved_uids.push(message.uid);
				modseqs.push(message.modseq);
			}
		}

		// RFC 7162 §3.1.5: a search that tests MODSEQ reports the highest
		// mod-sequence of the messages it returns.
		let modseq = if super::super::condstore::uses_modseq(criteria) {
			let opts = return_opts.or(self.imap4rev2.then_some(&[ReturnOpt::All][..]));
			super::super::condstore::reply_modseq(&modseqs, opts)
		} else {
			None
		};
		let body = match return_opts {
			Some(opts) => esearch_line(tag, uid, &hits, opts, modseq),
			None if self.imap4rev2 => esearch_line(tag, uid, &hits, &[ReturnOpt::All], modseq),
			None => {
				let mut line = String::from("* SEARCH");
				for hit in &hits {
					line.push_str(&format!(" {hit}"));
				}
				if let Some(modseq) = modseq {
					line.push_str(&format!(" (MODSEQ {modseq})"));
				}
				line.push_str("\r\n");
				line
			}
		};
		// SEARCHRES (RFC 5182): the `SAVE` return option stores the result
		// set so subsequent commands can reference it via `$`. We replace the
		// reservation on every successful SEARCH with SAVE, never merge. A
		// failing SEARCH MUST NOT touch the saved set. The stored values are
		// always UIDs; `are_uids` flags the kind of SAVE that produced them
		// so FETCH/STORE/COPY can still distinguish UID SEARCH from plain
		// SEARCH at the protocol boundary.
		if let Some(opts) = return_opts
			&& opts.contains(&ReturnOpt::Save)
		{
			self.saved_search = Some(super::super::SavedSearch {
				are_uids: uid,
				uids: saved_uids,
			});
		}
		Output::text(format!("{body}{tag} OK SEARCH completed\r\n"))
	}

	/// MULTISEARCH (RFC 7377): search every resolved mailbox and emit one
	/// `* ESEARCH` line per mailbox that produced output. Results are always
	/// UIDs, correlated by `MAILBOX`/`UIDVALIDITY`.
	pub(in crate::imap::session) fn esearch(
		&mut self,
		tag: &str,
		sources: &[SearchScope],
		criteria: &[SearchKey],
		return_opts: &[ReturnOpt],
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} BAD not authenticated\r\n"));
		};

		let mut mailboxes = match self.resolve_scopes(sources, &account) {
			Some(mailboxes) => mailboxes,
			None => return Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		};
		mailboxes.dedup();

		let mut body = String::new();
		for name in &mailboxes {
			let Ok(snapshot) = self.open_snapshot(&account, name) else {
				continue;
			};
			let hits = matching_uids(&snapshot, criteria);
			body.push_str(&esearch_multi_line(
				tag,
				&self.mailbox_astring(name),
				snapshot.uid_validity(),
				&hits,
				return_opts,
			));
		}
		Output::text(format!("{body}{tag} OK SEARCH completed\r\n"))
	}

	/// Resolve MULTISEARCH source scopes to a concrete, ordered mailbox list.
	/// Returns `None` only when `selected` is requested without a selected
	/// mailbox (a protocol error).
	fn resolve_scopes(&self, sources: &[SearchScope], account: &str) -> Option<Vec<String>> {
		let mut names = Vec::new();
		for source in sources {
			match source {
				SearchScope::Selected => match &self.state {
					State::Selected { mailbox, .. } => names.push(mailbox.clone()),
					_ => return None,
				},
				SearchScope::Inboxes => names.push("INBOX".to_string()),
				SearchScope::Personal => {
					names.extend(mailbox::list(&self.data_dir, account));
				}
				SearchScope::Subscribed => {
					names.extend(mailbox::list_subscribed(&self.data_dir, account));
				}
				SearchScope::Subtree(roots) => {
					names.extend(subtree(&self.data_dir, account, roots, false));
				}
				SearchScope::SubtreeOne(roots) => {
					names.extend(subtree(&self.data_dir, account, roots, true));
				}
				SearchScope::Mailboxes(list) => names.extend(list.iter().cloned()),
			}
		}
		Some(names)
	}
}

/// UIDs of every message in `snapshot` matching all search keys.
fn matching_uids(snapshot: &Snapshot, criteria: &[SearchKey]) -> Vec<u32> {
	let total = snapshot.max_identifier(false);
	let maxima = (total, snapshot.max_identifier(true));
	let mut hits = Vec::new();
	for seqno in 1..=total {
		let Some(message) = snapshot.by_sequence(seqno) else {
			continue;
		};
		let mut content: Option<String> = None;
		if criteria
			.iter()
			.all(|key| search_matches(key, message, seqno, maxima, snapshot, &mut content, &[]))
		{
			hits.push(message.uid);
		}
	}
	hits
}

/// Expand SUBTREE / SUBTREE-ONE roots into matching mailbox names. With
/// `one_level`, only the root and its immediate children are included;
/// otherwise the whole subtree (the hierarchy separator is `/`).
fn subtree(
	data_dir: &std::path::Path,
	account: &str,
	roots: &[String],
	one_level: bool,
) -> Vec<String> {
	let all = mailbox::list(data_dir, account);
	let mut out = Vec::new();
	for root in roots {
		let prefix = format!("{root}/");
		for name in &all {
			if name == root {
				out.push(name.clone());
			} else if let Some(rest) = name.strip_prefix(&prefix)
				&& (!one_level || !rest.contains('/'))
			{
				out.push(name.clone());
			}
		}
	}
	out
}
