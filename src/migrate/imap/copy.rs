//! Copying one remote folder into one local mailbox, a batch at a time.
//!
//! The order of a batch is: fetch it whole, mark the folder's state as
//! "batch in progress", store the messages in UID order, then record the
//! last UID handled. A server that fails mid-batch therefore leaves nothing
//! of that batch stored and the state untouched; a local failure records
//! exactly the messages stored before it; only a process killed while
//! storing leaves the in-progress mark, and the next run then checks each
//! message against the mailbox before storing it.

use std::time::Instant;

use super::client::Client;
use super::dedupe::{self, Index};
use super::folders::Plan;
use super::parse::{Fetched, Listed};
use super::state::{FolderState, StateDir};
use super::{FolderReport, MigrateError, Progress, Settings, Target};
use crate::imap::mailbox::{self, Flag};

/// Copy `plan`'s folder into `report.local`, recording progress in
/// `states` and what was done in `report`, which stays accurate when the
/// copy stops early.
pub(super) async fn folder(
	client: &mut Client,
	plan: &Plan,
	report: &mut FolderReport,
	states: &StateDir,
	target: &mut Target,
	settings: &Settings,
	progress: &mut dyn Progress,
) -> Result<(), MigrateError> {
	let started = Instant::now();
	let local = report.local.clone();
	let local = local.as_str();
	let examined = client.examine(&plan.remote).await?;
	let saved = states.load(&plan.remote).map_err(MigrateError::State)?;
	let resumable = |state: &FolderState| {
		examined.uid_validity != 0 && state.uid_validity == examined.uid_validity
	};
	let (from, dedupe) = match &saved {
		Some(state) if resumable(state) => (state.last_uid.saturating_add(1), state.in_progress),
		Some(_) => {
			report.restarted = true;
			(1, true)
		}
		// A server without UIDVALIDITY gives no stable UIDs to resume from.
		None => (1, examined.uid_validity == 0),
	};
	let mut state = FolderState {
		folder: plan.display.clone(),
		uid_validity: examined.uid_validity,
		last_uid: from - 1,
		in_progress: false,
		copied: saved.as_ref().map_or(0, |state| state.copied),
	};
	let listed = if examined.exists == 0 {
		Vec::new()
	} else {
		client
			.list_uids(from, examined.exists as usize + 16)
			.await?
	};
	report.messages = listed.len() as u64;
	report.planned_bytes = listed.iter().map(|item| item.size).sum();
	if settings.dry_run {
		report.seconds = started.elapsed().as_secs_f64();
		return Ok(());
	}
	if !mailbox::exists(&target.data_dir, &target.account, local) {
		mailbox::create(&target.data_dir, &target.account, local).map_err(MigrateError::Storage)?;
	}
	let mut index = if dedupe {
		let scanned = Index::scan(&target.data_dir, &target.account, local, &target.crypto);
		Some(scanned.map_err(MigrateError::Storage)?)
	} else {
		None
	};
	progress.folder_start(report);
	for batch in batches(&listed, settings) {
		let wanted: Vec<u32> = batch
			.iter()
			.filter(|item| item.size <= settings.limits.literal as u64)
			.map(|item| item.uid)
			.collect();
		report.too_large += (batch.len() - wanted.len()) as u64;
		let mut fetched = if wanted.is_empty() {
			Vec::new()
		} else {
			client.fetch(&wanted).await?
		};
		fetched.sort_by_key(|item| item.uid);
		report.vanished += (wanted.len() - fetched.len()) as u64;
		state.in_progress = true;
		states
			.save(&plan.remote, &state)
			.map_err(MigrateError::State)?;
		for item in fetched {
			let uid = item.uid;
			if let Err(error) = store(item, local, target, &mut index, report) {
				state.in_progress = false;
				state.copied = state.copied.saturating_add(report.copied);
				states
					.save(&plan.remote, &state)
					.map_err(MigrateError::State)?;
				return Err(error);
			}
			state.last_uid = uid;
		}
		state.last_uid = state.last_uid.max(batch.last().map_or(0, |item| item.uid));
		state.in_progress = false;
		states
			.save(&plan.remote, &state)
			.map_err(MigrateError::State)?;
		report.seconds = started.elapsed().as_secs_f64();
		progress.folder_progress(report);
	}
	state.copied = state.copied.saturating_add(report.copied);
	states
		.save(&plan.remote, &state)
		.map_err(MigrateError::State)?;
	report.seconds = started.elapsed().as_secs_f64();
	Ok(())
}

/// Store one fetched message, unless it is marked for deletion or already
/// stored. Refuses it when the account quota would be exceeded.
fn store(
	item: Fetched,
	local: &str,
	target: &mut Target,
	index: &mut Option<Index>,
	report: &mut FolderReport,
) -> Result<(), MigrateError> {
	let Some(body) = item.body else {
		report.vanished += 1;
		return Ok(());
	};
	let mut flags = Vec::new();
	for raw in &item.flags {
		match Flag::parse(raw) {
			// A message waiting to be expunged is not carried over.
			Some(Flag::Deleted) => {
				report.deleted += 1;
				return Ok(());
			}
			Some(flag) => flags.push(flag),
			// `\Recent` and unknown system flags cannot be set by a client.
			None => {}
		}
	}
	mailbox::dedup_flags(&mut flags);
	let mut keywords = 0;
	flags.retain(|flag| {
		keywords += usize::from(flag.is_keyword());
		!flag.is_keyword() || keywords <= crate::imap::keyword::MAX_KEYWORDS_PER_MESSAGE
	});
	if let Some(index) = index
		&& index.claim(&dedupe::key(&body))
	{
		report.duplicates += 1;
		return Ok(());
	}
	let size = body.len() as u64;
	if let Some(limit) = target.quota
		&& target.usage.saturating_add(size) > limit
	{
		return Err(MigrateError::Quota {
			account: target.account.clone(),
			limit,
			usage: target.usage,
			needed: size,
		});
	}
	mailbox::append_dated(
		&target.data_dir,
		&target.account,
		local,
		&flags,
		item.internal_date,
		&body,
		&target.crypto,
	)
	.map_err(MigrateError::Storage)?;
	target.usage = target.usage.saturating_add(size);
	report.copied += 1;
	report.bytes += size;
	Ok(())
}

/// Split `listed` into batches of at most `settings.batch_messages`
/// messages and `settings.batch_bytes` octets (a message larger than that
/// travels alone).
fn batches<'a>(listed: &'a [Listed], settings: &Settings) -> Vec<&'a [Listed]> {
	let mut out = Vec::new();
	let mut start = 0;
	while start < listed.len() {
		let mut end = start;
		let mut bytes = 0u64;
		while end < listed.len()
			&& end - start < settings.batch_messages
			&& (end == start || bytes.saturating_add(listed[end].size) <= settings.batch_bytes)
		{
			bytes = bytes.saturating_add(listed[end].size);
			end += 1;
		}
		out.push(&listed[start..end]);
		start = end;
	}
	out
}
