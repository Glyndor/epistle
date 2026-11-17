mod content;
mod filter;
mod page;
mod sort;

use std::collections::HashSet;
use std::path::Path;
use std::time::SystemTime;

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::state;

pub(super) use page::MAX_QUERY_LIMIT;
pub(super) const MAX_QUERY_RESULTS: usize = 100_000;
pub(super) const MAX_QUERY_MAILBOXES: usize = 1_000;
pub(super) const MAX_SEARCH_MESSAGES: usize = 10_000;
pub(super) const MAX_SEARCH_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_SEARCH_HEADER_BYTES: usize = 256 * 1024;
pub(super) const LIMIT_RESULTS: &str = "maxEmailQueryResults";
pub(super) const LIMIT_MAILBOXES: &str = "maxEmailQueryMailboxes";
pub(super) const LIMIT_SEARCH_MESSAGES: &str = "maxEmailQuerySearchMessages";
pub(super) const LIMIT_SEARCH_BYTES: &str = "maxEmailQuerySearchBytes";
pub(super) const LIMIT_SEARCH_HEADER_BYTES: &str = "maxEmailQuerySearchHeaderBytes";

pub(super) struct InputError {
	kind: &'static str,
	description: String,
}

impl InputError {
	pub(super) fn invalid(description: impl Into<String>) -> Self {
		Self {
			kind: "invalidArguments",
			description: description.into(),
		}
	}

	pub(super) fn unsupported_filter() -> Self {
		Self {
			kind: "unsupportedFilter",
			description: "filter property is not supported".to_string(),
		}
	}

	pub(super) fn unsupported_sort() -> Self {
		Self {
			kind: "unsupportedSort",
			description: "sort property is not supported".to_string(),
		}
	}
}

pub(super) enum Failure {
	Method(Value),
	Limit(&'static str, String),
}

struct Candidate {
	id: String,
	uid: u32,
	received_at: SystemTime,
}

pub(super) fn query(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Result<Value, Failure> {
	let account =
		state::admitted_account(state, principal, args, call_id).map_err(Failure::Method)?;
	let filter =
		filter::Filter::parse(args.get("filter")).map_err(|error| input_failure(error, call_id))?;
	let sort =
		sort::Sort::parse(args.get("sort")).map_err(|error| input_failure(error, call_id))?;
	let page = page::Page::parse(args).map_err(|error| input_failure(error, call_id))?;
	let mailboxes = query_mailboxes(state, account.as_str(), &filter);
	preflight(state, account.as_str(), &mailboxes, &filter, call_id)?;
	let mut candidates = collect(state, account.as_str(), &mailboxes, &filter, call_id)?;
	sort_candidates(&mut candidates, sort.ascending());
	let total = candidates.len();
	let start = start_position(&candidates, &page, call_id)?;
	let ids = candidates
		.get(start..)
		.into_iter()
		.flatten()
		.take(page.limit())
		.map(|candidate| candidate.id.clone())
		.collect::<Vec<_>>();
	let query_state = state::email_get_state(state.data_dir(), account.as_str())
		.unwrap_or_else(|| "0".to_string());
	let can_calculate_changes = replayable_mailboxes(state, account.as_str(), args).is_some();
	let mut response = json!({
		"accountId": account,
		"queryState": query_state,
		"canCalculateChanges": can_calculate_changes,
		"position": start,
		"ids": ids,
	});
	if page.include_total() {
		response["total"] = json!(total);
	}
	if page.server_adjusted_limit() {
		response["limit"] = json!(page::MAX_QUERY_LIMIT);
	}
	Ok(json!(["Email/query", response, call_id]))
}

pub(super) fn replayable_mailboxes(
	state: &ApiState,
	account: &str,
	args: &Value,
) -> Option<Vec<String>> {
	let filter = filter::Filter::parse(args.get("filter")).ok()?;
	let sort = sort::Sort::parse(args.get("sort")).ok()?;
	if !sort.replayable() {
		return None;
	}
	match filter.replayable_scope()? {
		filter::ReplayScope::All => Some(crate::imap::mailbox::list(state.data_dir(), account)),
		filter::ReplayScope::Mailbox(mailbox) => Some(vec![mailbox]),
	}
}

pub(super) fn replayable_ids(
	state: &ApiState,
	account: &str,
	mailboxes: &[String],
) -> Option<Vec<String>> {
	if mailboxes.len() > MAX_QUERY_MAILBOXES {
		return None;
	}
	let mut count = 0usize;
	for mailbox in mailboxes {
		count = count.saturating_add(mailbox_message_count(state.data_dir(), account, mailbox)?);
		if count > MAX_QUERY_RESULTS {
			return None;
		}
	}
	let mut candidates = Vec::with_capacity(count);
	let mut seen = HashSet::new();
	for mailbox in mailboxes {
		let snapshot = crate::imap::mailbox::Snapshot::open(
			state.data_dir(),
			account,
			mailbox,
			state.crypto(),
		)
		.ok()?;
		for message in snapshot.messages() {
			if candidates.len() >= MAX_QUERY_RESULTS {
				return None;
			}
			let id = message.id().to_string();
			if seen.insert(id.clone()) {
				candidates.push(Candidate {
					id,
					uid: message.uid,
					received_at: message.internal_date,
				});
			}
		}
	}
	sort_candidates(&mut candidates, false);
	Some(
		candidates
			.into_iter()
			.map(|candidate| candidate.id)
			.collect(),
	)
}

fn input_failure(error: InputError, call_id: &str) -> Failure {
	Failure::Method(json!([
		"error",
		{ "type": error.kind, "description": error.description },
		call_id
	]))
}

fn query_mailboxes(state: &ApiState, account: &str, filter: &filter::Filter) -> Vec<String> {
	if let Some(mailbox) = filter.mailbox_scope() {
		return vec![mailbox];
	}
	crate::imap::mailbox::list(state.data_dir(), account)
}

fn preflight(
	state: &ApiState,
	account: &str,
	mailboxes: &[String],
	filter: &filter::Filter,
	call_id: &str,
) -> Result<(), Failure> {
	if mailboxes.len() > MAX_QUERY_MAILBOXES {
		return Err(Failure::Limit(
			LIMIT_MAILBOXES,
			format!("query would examine more than {MAX_QUERY_MAILBOXES} mailboxes"),
		));
	}
	let mut count = 0usize;
	for mailbox in mailboxes {
		let Some(messages) = mailbox_message_count(state.data_dir(), account, mailbox) else {
			return Err(Failure::Method(json!([
				"error",
				{ "type": "serverFail" },
				call_id
			])));
		};
		count = count.saturating_add(messages);
		if count > MAX_QUERY_RESULTS {
			return Err(Failure::Limit(
				LIMIT_RESULTS,
				format!("query would examine more than {MAX_QUERY_RESULTS} messages"),
			));
		}
	}
	if !filter.needs_content() {
		return Ok(());
	}
	if count > MAX_SEARCH_MESSAGES {
		return Err(Failure::Limit(
			LIMIT_SEARCH_MESSAGES,
			format!("text search would examine more than {MAX_SEARCH_MESSAGES} messages"),
		));
	}
	let mut bytes = 0u64;
	for mailbox in mailboxes {
		let snapshot = match crate::imap::mailbox::Snapshot::open(
			state.data_dir(),
			account,
			mailbox,
			state.crypto(),
		) {
			Ok(snapshot) => snapshot,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(_) => {
				return Err(Failure::Method(json!([
					"error",
					{ "type": "serverFail" },
					call_id
				])));
			}
		};
		for message in snapshot.messages() {
			bytes = bytes.saturating_add(message.size);
			if bytes > MAX_SEARCH_BYTES {
				return Err(Failure::Limit(
					LIMIT_SEARCH_BYTES,
					format!("text search would read more than {MAX_SEARCH_BYTES} octets"),
				));
			}
		}
	}
	Ok(())
}

fn collect(
	state: &ApiState,
	account: &str,
	mailboxes: &[String],
	filter: &filter::Filter,
	call_id: &str,
) -> Result<Vec<Candidate>, Failure> {
	let mut candidates = Vec::new();
	let mut seen = HashSet::new();
	let mut considered = 0usize;
	let mut bytes = 0u64;
	for mailbox in mailboxes {
		let snapshot = match crate::imap::mailbox::Snapshot::open(
			state.data_dir(),
			account,
			mailbox,
			state.crypto(),
		) {
			Ok(snapshot) => snapshot,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(_) => {
				return Err(Failure::Method(json!([
					"error",
					{ "type": "serverFail" },
					call_id
				])));
			}
		};
		for message in snapshot.messages() {
			considered += 1;
			if considered > MAX_QUERY_RESULTS {
				return Err(Failure::Limit(
					LIMIT_RESULTS,
					format!("query would examine more than {MAX_QUERY_RESULTS} messages"),
				));
			}
			let content = if filter.needs_content() {
				bytes = bytes.saturating_add(message.size);
				if bytes > MAX_SEARCH_BYTES {
					return Err(Failure::Limit(
						LIMIT_SEARCH_BYTES,
						format!("text search would read more than {MAX_SEARCH_BYTES} octets"),
					));
				}
				let raw = snapshot.read(message).map_err(|_| {
					Failure::Method(json!([
						"error",
						{ "type": "serverFail" },
						call_id
					]))
				})?;
				let (header, _) = crate::util::header_block::split_at_blank_line(&raw);
				if header.len() > MAX_SEARCH_HEADER_BYTES {
					return Err(Failure::Limit(
						LIMIT_SEARCH_HEADER_BYTES,
						format!(
							"text search would read a header block over {MAX_SEARCH_HEADER_BYTES} octets"
						),
					));
				}
				Some(content::Content::from_raw(&raw))
			} else {
				None
			};
			if !filter.matches(mailbox, message, content.as_ref()) {
				continue;
			}
			let id = message.id().to_string();
			if seen.insert(id.clone()) {
				candidates.push(Candidate {
					id,
					uid: message.uid,
					received_at: message.internal_date,
				});
			}
		}
	}
	Ok(candidates)
}

fn sort_candidates(candidates: &mut [Candidate], ascending: bool) {
	candidates.sort_by(|left, right| {
		let order = left
			.received_at
			.cmp(&right.received_at)
			.then_with(|| left.uid.cmp(&right.uid))
			.then_with(|| left.id.cmp(&right.id));
		if ascending { order } else { order.reverse() }
	});
}

fn start_position(
	candidates: &[Candidate],
	page: &page::Page,
	call_id: &str,
) -> Result<usize, Failure> {
	let total = candidates.len() as i128;
	let start = if let Some(anchor) = page.anchor() {
		let index = candidates
			.iter()
			.position(|candidate| candidate.id == anchor)
			.ok_or_else(|| {
				Failure::Method(json!([
					"error",
					{ "type": "anchorNotFound" },
					call_id
				]))
			})?;
		(index as i128 + page.anchor_offset() as i128).max(0)
	} else if page.position() < 0 {
		(total + page.position() as i128).max(0)
	} else {
		page.position() as i128
	};
	Ok(start.min(total) as usize)
}

fn mailbox_message_count(data_dir: &Path, account: &str, mailbox: &str) -> Option<usize> {
	let directory = crate::imap::mailbox::mailbox_dir(data_dir, account, mailbox)?;
	match crate::util::fs_walk::rooted::read_dir(data_dir, &directory) {
		Ok(entries) => Some(
			entries
				.flatten()
				.filter(|entry| {
					entry.file_type().is_ok_and(|kind| kind.is_file())
						&& entry
							.file_name()
							.to_str()
							.is_some_and(|name| name.ends_with(".eml"))
				})
				.count(),
		),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(0),
		Err(_) => None,
	}
}
