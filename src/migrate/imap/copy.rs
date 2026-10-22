//! Copying one remote folder into one local mailbox, a batch at a time.
//!
//! The order of a batch is: fetch it whole, mark the folder's state as
//! "batch in progress", store the messages in UID order, record what the batch
//! confirmed in the folder's ledger, then record the last UID handled. A server
//! that fails mid-batch therefore leaves nothing of that batch stored and the
//! state untouched. A local storage failure or an interrupted write records
//! what the batch had already stored and leaves the in-progress mark. Recovery
//! replays the confirmed prefix, skipping what the ledger already confirms and
//! matching the rest against pending copies, and stays active until the whole
//! folder has been replayed.

use std::time::Instant;

use super::client::Client;
use super::dedupe::{self, Index};
use super::folders::Plan;
use super::ledger::{self, Fingerprint};
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
	// What earlier runs already confirmed for this folder. It is the only
	// record of a message that no longer is in the local mailbox, so it is
	// never downloaded or stored again.
	let mut ledger = states
		.ledger(&plan.remote, examined.uid_validity, !settings.dry_run)
		.map_err(MigrateError::State)?;
	ledger::charge(&mut client.metadata)?;
	let resumable = |state: &FolderState| {
		examined.uid_validity != 0 && state.uid_validity == examined.uid_validity
	};
	let (mut from, dedupe) = match &saved {
		Some(state) if resumable(state) && !state.in_progress => {
			(state.last_uid.saturating_add(1), false)
		}
		// Replay the confirmed prefix too, consuming its identities before
		// matching any copies left by the interrupted batch.
		Some(state) if resumable(state) => (1, true),
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
		in_progress: dedupe,
		copied: saved.as_ref().map_or(0, |state| state.copied),
	};
	let mut index = None;
	let mut initialized = false;
	let mut windows = 0u64;
	let mut width = 10_000u32;
	let mut tail = false;
	let window_limit = 32 * (u64::from(examined.exists) + 1);
	loop {
		let to = examined
			.uid_next
			.checked_sub(1)
			.filter(|_| !tail)
			.map(|last| from.saturating_add(width - 1).min(last));
		let listed = if (examined.exists == 0 && examined.uid_next != 0)
			|| to.is_some_and(|last| from > last)
		{
			Vec::new()
		} else {
			if windows >= window_limit {
				return Err(super::ClientError::Protocol(
					"IMAP UID window limit reached; saved progress is retained; run again to resume".into(),
				).into());
			}
			windows += 1;
			client
				.list_uids(from, to, (examined.exists as usize).saturating_add(16))
				.await?
		};
		let count = report.messages.saturating_add(listed.len() as u64);
		let allowance = if examined.uid_next == 0 { 16 } else { 0 };
		if count > u64::from(examined.exists) + allowance {
			return Err(super::ClientError::Protocol(
				"IMAP listing exceeds EXISTS; saved progress is retained; run again to resume"
					.into(),
			)
			.into());
		}
		if count > u64::from(examined.exists) {
			tracing::warn!(
				folder = %plan.display,
				exists = examined.exists,
				listed = count,
				"IMAP mailbox grew after EXAMINE without UIDNEXT"
			);
		}
		// Widen empty gaps without collecting an unbounded UID list.
		width = if listed.is_empty() {
			width.saturating_mul(2)
		} else {
			10_000
		};
		report.messages += listed.len() as u64;
		report.planned_bytes = listed.iter().fold(report.planned_bytes, |total, item| {
			total.saturating_add(item.size)
		});
		if !settings.dry_run {
			if !initialized {
				if !mailbox::exists(&target.data_dir, &target.account, local) {
					mailbox::create(&target.data_dir, &target.account, local)
						.map_err(MigrateError::Storage)?;
				}
				if dedupe {
					index = Some(Index::scan(
						&target.data_dir,
						&target.account,
						local,
						&target.crypto,
						&mut client.metadata,
						target.max_message_size,
						saved.as_ref().is_some_and(|state| state.in_progress),
					)?);
				}
				initialized = true;
				progress.folder_start(report);
			}
			// What the ledger confirms is not downloaded again, and consumes
			// the local copy it would have matched, so that two identical
			// messages in the source still end up as two here.
			let mut pending = Vec::with_capacity(listed.len());
			for item in listed.iter().copied() {
				match ledger.fingerprint(item.uid).map_err(MigrateError::State)? {
					Some(fingerprint) => {
						report.confirmed += 1;
						if let Some(index) = index.as_mut() {
							index
								.claim_fingerprint(&fingerprint)
								.map_err(MigrateError::Storage)?;
						}
					}
					None => pending.push(item),
				}
			}
			for batch in batches(&pending, settings) {
				let wanted: Vec<Listed> = batch
					.iter()
					.filter(|item| item.size <= settings.limits.literal as u64)
					.copied()
					.collect();
				report.too_large += (batch.len() - wanted.len()) as u64;
				let mut fetched = if wanted.is_empty() {
					Vec::new()
				} else {
					// One batch holds at most batch_bytes, plus one message that is
					// larger on its own: what the server declared does not decide.
					let budget = settings
						.batch_bytes
						.saturating_add(settings.limits.literal as u64);
					client.fetch(&wanted, budget).await?
				};
				fetched.sort_by_key(|item| item.uid);
				fetched.dedup_by_key(|item| item.uid);
				report.vanished += (wanted.len() - fetched.len()) as u64;
				state.in_progress = true;
				states
					.save(&plan.remote, &state)
					.map_err(MigrateError::State)?;
				let mut settled: Vec<(u32, Fingerprint)> = Vec::new();
				for item in fetched {
					let uid = item.uid;
					match store(item, local, target, &mut index, report) {
						Ok(Some(fingerprint)) => settled.push((uid, fingerprint)),
						Ok(None) => {}
						Err(error) => {
							// What the batch stored before the stop is in the
							// local mailbox, so it is recorded now, as a batch
							// that completes records it: a folder that has to
							// be replayed skips those messages instead of
							// fetching them again.
							if let Err(refused) = ledger.confirm(&settled) {
								tracing::warn!(
									folder = %plan.display,
									error = %refused,
									"the messages stored before the stop are not recorded: the next run matches them against the local mailbox again"
								);
							}
							state.in_progress = dedupe || matches!(error, MigrateError::Storage(_));
							state.copied = state.copied.saturating_add(report.copied);
							states
								.save(&plan.remote, &state)
								.map_err(MigrateError::State)?;
							return Err(error);
						}
					}
					state.last_uid = uid;
				}
				// The messages of this batch are stored and synchronized, so
				// record them before the checkpoint that confirms it.
				ledger.confirm(&settled).map_err(MigrateError::State)?;
				state.last_uid = state.last_uid.max(batch.last().map_or(0, |item| item.uid));
				// Keep replay active across checkpoints until every old copy
				// has been accounted for, including after another interruption.
				state.in_progress = dedupe;
				states
					.save(&plan.remote, &state)
					.map_err(MigrateError::State)?;
				report.seconds = started.elapsed().as_secs_f64();
				progress.folder_progress(report);
			}
			if let Some(end) = to {
				state.last_uid = state.last_uid.max(end);
			}
			states
				.save(&plan.remote, &state)
				.map_err(MigrateError::State)?;
		}
		match to {
			Some(end) if examined.exists > 0 && end < examined.uid_next - 1 => from = end + 1,
			Some(_) if examined.exists > 0 => {
				// UIDNEXT is a hint from the source, so inspect its remaining UIDs too.
				from = from.max(examined.uid_next);
				tail = true;
			}
			_ => break,
		}
	}
	if settings.dry_run {
		report.seconds = started.elapsed().as_secs_f64();
		return Ok(());
	}
	state.copied = state.copied.saturating_add(report.copied);
	state.in_progress = false;
	states
		.save(&plan.remote, &state)
		.map_err(MigrateError::State)?;
	report.seconds = started.elapsed().as_secs_f64();
	Ok(())
}

/// Store one fetched message, unless it is marked for deletion or already
/// stored. Refuses it when the account quota would be exceeded. Returns the
/// identity fingerprint when the message settled as present locally, stored or
/// already here, and `None` when it was left out.
fn store(
	item: Fetched,
	local: &str,
	target: &mut Target,
	index: &mut Option<Index>,
	report: &mut FolderReport,
) -> Result<Option<Fingerprint>, MigrateError> {
	let Some(body) = item.body else {
		report.vanished += 1;
		return Ok(None);
	};
	let mut flags = Vec::new();
	for raw in &item.flags {
		match Flag::parse(raw) {
			// A message waiting to be expunged is not carried over.
			Some(Flag::Deleted) => {
				report.deleted += 1;
				return Ok(None);
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
	let key = dedupe::key(&body);
	let fingerprint = dedupe::fingerprint(&key);
	if let Some(index) = index
		&& index.claim(&key).map_err(MigrateError::Storage)?
	{
		report.duplicates += 1;
		return Ok(Some(fingerprint));
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
	let id = mailbox::append_dated(
		&target.data_dir,
		&target.account,
		local,
		&flags,
		item.internal_date,
		&body,
		&target.crypto,
	)
	.map_err(MigrateError::Storage)?;
	super::durability::message(&target.data_dir, &target.account, local, id)
		.map_err(MigrateError::Storage)?;
	target.usage = target.usage.saturating_add(size);
	report.copied += 1;
	report.bytes += size;
	Ok(Some(fingerprint))
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
