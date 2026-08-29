//! IMAP COPY/MOVE/SEARCH/ESEARCH command handlers.

use super::super::command::{ReturnOpt, SearchScope, SequenceSet};
use super::codes::{copyuid_code, esearch_line, esearch_multi_line};
use super::helpers::search_matches;
use super::mailbox::{self, Snapshot};
use super::state::State;
use super::{Output, SearchKey, Session};

impl Session {
	pub(super) fn copy(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		target: &str,
		uid: bool,
		remove_source: bool,
	) -> Output {
		let uidonly = self.uidonly;
		let data_dir = self.data_dir.clone();
		let crypto = self.crypto.clone();
		// Capture the SEARCHRES `$` set before the mutable borrow of `self.state`,
		// since `saved_seqnos_for` reads `self` immutably.
		let saved = self.saved_seqnos_for(uid);
		let State::Selected {
			account,
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if remove_source && *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let account = account.clone();
		if !mailbox::exists(&data_dir, &account, target) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut matched = Vec::new();
		let mut source_uids = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if sequence.contains(selector, total, &saved) {
				matched.push(sequence_number);
				source_uids.push(message.uid);
			}
		}

		// Copy all before removing any: a failed copy must not lose mail.
		let mut dest_ids = Vec::new();
		for sequence_number in &matched {
			let Some(message) = snapshot.by_sequence(*sequence_number) else {
				return Output::text(format!("{tag} NO message vanished\r\n"));
			};
			let data = match snapshot.read(message) {
				Ok(data) => data,
				Err(_) => return Output::text(format!("{tag} NO message unavailable\r\n")),
			};
			match mailbox::append(&data_dir, &account, target, &message.flags, &data, &crypto) {
				Ok(id) => dest_ids.push(id),
				Err(_) => return Output::text(format!("{tag} NO copy failed\r\n")),
			}
		}

		// UIDPLUS: the source and destination UID sets (RFC 4315).
		let copyuid = copyuid_code(&data_dir, &account, target, &source_uids, &dest_ids);

		let mut response = String::new();
		if remove_source {
			// Remove bottom-up so earlier sequence numbers stay valid, but
			// emit EXPUNGE top-down with renumber-correct values.
			for (offset, sequence_number) in matched.iter().enumerate() {
				let current = sequence_number - u32::try_from(offset).unwrap_or(0);
				if snapshot.remove_at(current).is_err() {
					return Output::text(format!("{tag} NO move failed\r\n"));
				}
				if !uidonly {
					response.push_str(&format!("* {current} EXPUNGE\r\n"));
				}
			}
			// UIDONLY: report removals as a single VANISHED with UIDs.
			if uidonly && !source_uids.is_empty() {
				response.push_str(&format!(
					"* VANISHED {}\r\n",
					super::codes::uid_set(&source_uids)
				));
			}
		}
		let verb = if remove_source { "MOVE" } else { "COPY" };
		response.push_str(&format!("{tag} OK {copyuid}{verb} completed\r\n"));
		Output::text(response)
	}

	pub(super) fn search(
		&mut self,
		tag: &str,
		criteria: &[SearchKey],
		uid: bool,
		return_opts: Option<&[ReturnOpt]>,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		// SEARCH criteria never carry SEARCHRES `$` placeholders — only the
		// consuming commands (FETCH/STORE/COPY/UID EXPUNGE) do — so the saved
		// set is irrelevant here.
		let mut hits = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content, &[]));
			if matches {
				hits.push(if uid { message.uid } else { seqno });
			}
		}

		let body = match return_opts {
			Some(opts) => esearch_line(tag, uid, &hits, opts),
			None => {
				let mut line = String::from("* SEARCH");
				for hit in &hits {
					line.push_str(&format!(" {hit}"));
				}
				line.push_str("\r\n");
				line
			}
		};
		// SEARCHRES (RFC 5182): the `SAVE` return option stores the result
		// set so subsequent commands can reference it via `$`. We replace the
		// reservation on every successful SEARCH with SAVE, never merge. A
		// failing SEARCH MUST NOT touch the saved set.
		if let Some(opts) = return_opts
			&& opts.contains(&ReturnOpt::Save)
		{
			self.saved_search = Some(super::SavedSearch {
				are_uids: uid,
				values: hits.clone(),
			});
		}
		Output::text(format!("{body}{tag} OK SEARCH completed\r\n"))
	}

	/// MULTISEARCH (RFC 7377): search every resolved mailbox and emit one
	/// `* ESEARCH` line per mailbox that produced output. Results are always
	/// UIDs, correlated by `MAILBOX`/`UIDVALIDITY`.
	pub(super) fn esearch(
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
				name,
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
	let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
	let mut hits = Vec::new();
	for seqno in 1..=total {
		let Some(message) = snapshot.by_sequence(seqno) else {
			continue;
		};
		let mut content: Option<String> = None;
		if criteria
			.iter()
			.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content, &[]))
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
