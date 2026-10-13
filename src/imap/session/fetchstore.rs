//! IMAP FETCH and STORE handlers, including CONDSTORE conditional
//! operations (RFC 7162).

use super::super::command::SequenceSet;
use super::mailbox::{Flag, Snapshot, render_flags};
use super::select::flags_line_for;
use super::state::State;
use super::{Output, Session, StoreMode};

/// The flag set a STORE in `mode` with `flags` leaves on a message that
/// carries `current`. Keywords match without regard to case, and the
/// result holds each flag once.
fn next_flags(mode: StoreMode, current: &[Flag], flags: &[Flag]) -> Vec<Flag> {
	let mut next: Vec<Flag> = match mode {
		StoreMode::Set => flags.to_vec(),
		StoreMode::Add => current.iter().chain(flags).cloned().collect(),
		StoreMode::Remove => current
			.iter()
			.filter(|flag| !super::mailbox::flag_set_contains(flags, flag))
			.cloned()
			.collect(),
	};
	super::mailbox::dedup_flags(&mut next);
	next
}

/// Every user keyword currently attached to any message in `snapshot`,
/// deduplicated case-insensitively. Used to detect when STORE newly
/// places a keyword on a message so the response can advertise it via
/// an updated FLAGS line (RFC 9051 7.3.5) before the FETCH that
/// mentions the keyword.
pub(super) fn collect_mailbox_keywords(snapshot: &Snapshot) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for message in snapshot.messages() {
		for keyword in super::mailbox::keywords_in(&message.flags) {
			let name = keyword.as_str().to_string();
			if !out
				.iter()
				.any(|existing| existing.eq_ignore_ascii_case(&name))
			{
				out.push(name);
			}
		}
	}
	out
}

impl Session {
	// CONDSTORE adds the seventh data argument; a params struct would not read
	// any clearer than the flat command shape here.
	#[allow(clippy::too_many_arguments)]
	pub(super) fn store(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		mode: StoreMode,
		flag_tokens: &[String],
		silent: bool,
		uid: bool,
		unchanged_since: Option<u64>,
	) -> Output {
		let uidonly = self.uidonly;
		// Capture the SEARCHRES `$` set before the mutable borrow of
		// `self.state`. The set is keyed by UID (§5182 §2.1); the resolver
		// turns it into the kind of values the loop expects (UIDs for UID
		// commands, current seqnos for non-UID commands), and the snapshot
		// it works against is the one this command will act on.
		let saved_search = self.saved_search.clone();
		// Cloned before `self.state` is borrowed mutably below.
		let training = self.training.clone();
		let State::Selected {
			snapshot,
			read_only,
			account,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		let account = account.clone();
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		// Resolve the SEARCHRES `$` placeholder against this snapshot. The
		// saved set is always keyed by UID; for UID commands the UIDs are
		// matched directly, for non-UID commands they are mapped through
		// the snapshot to current sequence numbers (expunged messages
		// drop out automatically per RFC 5182 §2.1).
		let saved = match saved_search.as_ref() {
			Some(saved) if saved.are_uids == uid => {
				if uid {
					saved.uids.clone()
				} else {
					saved
						.uids
						.iter()
						.filter_map(|u| snapshot.sequence_of_uid(*u))
						.collect()
				}
			}
			_ => Vec::new(),
		};

		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		super::mailbox::dedup_flags(&mut flags);
		// Per-message keyword cap, checked before any message is touched.
		// A FLAGS list over the cap is refused whatever the mailbox holds.
		if matches!(mode, StoreMode::Set) && super::mailbox::count_keywords(&flags).is_none() {
			return Output::text(format!(
				"{tag} BAD too many keywords (max {})\r\n",
				super::super::keyword::MAX_KEYWORDS_PER_MESSAGE
			));
		}

		let total = snapshot.max_identifier(false);
		let maximum = snapshot.max_identifier(uid);
		// +FLAGS overshoots only through what a message already carries,
		// so every selected message is checked first: either all of them
		// take the new keywords or none is changed.
		if matches!(mode, StoreMode::Add) {
			for sequence_number in 1..=total {
				let Some(message) = snapshot.by_sequence(sequence_number) else {
					continue;
				};
				let selector = if uid { message.uid } else { sequence_number };
				if sequence.contains(selector, maximum, &saved)
					&& super::mailbox::count_keywords(&next_flags(mode, &message.flags, &flags))
						.is_none()
				{
					return Output::text(format!(
						"{tag} NO [LIMIT] too many keywords on a message (max {})\r\n",
						super::super::keyword::MAX_KEYWORDS_PER_MESSAGE
					));
				}
			}
		}
		let mut response = String::new();
		let mut modified: Vec<u32> = Vec::new();
		// RFC 9051 7.3.5: any keyword a STORE places on a message for the
		// first time in this mailbox must appear in an untagged FLAGS
		// response before the FETCH that mentions it. Dovecot's imaptest
		// tracks the keyword set the client last heard about and treats
		// any FETCH that introduces a keyword the FLAGS list hasn't
		// advertised as a state error. Sampling the keyword set before
		// the loop lets the comparison stay cheap (a single pass over the
		// messages) and gives a deterministic answer when many messages
		// gain the same new keyword.
		let pre_keywords = collect_mailbox_keywords(snapshot);
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, maximum, &saved) {
				continue;
			}
			// CONDSTORE UNCHANGEDSINCE: a concurrently-changed message is not
			// updated; its UID is reported in the MODIFIED response code.
			if unchanged_since.is_some_and(|since| message.modseq > since) {
				modified.push(message.uid);
				continue;
			}
			let message_uid = message.uid;
			let updated = next_flags(mode, &message.flags, &flags);
			// The flags before `store_flags` rewrites them, and the file a
			// training job would name. The message itself is not read here.
			let previous_flags = message.flags.clone();
			let Ok(message_path) = snapshot.message_path(message) else {
				return Output::text(format!("{tag} NO cannot store flags\r\n"));
			};
			let stored = match snapshot.store_flags(sequence_number, updated) {
				Ok(stored) => stored.to_vec(),
				Err(_) => {
					return Output::text(format!("{tag} NO cannot store flags\r\n"));
				}
			};
			// A `$Junk` / `$NotJunk` change queues a training job. The
			// queue never waits and a full one drops the job, so the
			// STORE reply does not depend on it.
			if let Some(queue) = &training {
				super::super::junk_trainer::enqueue_junk_transition(
					queue,
					&account,
					&previous_flags,
					&stored,
					message_path,
				);
			}
			let stored_render = render_flags(&stored);
			if !silent {
				// CONDSTORE: a conditional STORE reports the new mod-sequence.
				let modseq = snapshot.by_sequence(sequence_number).map(|m| m.modseq);
				let modseq = match (unchanged_since, modseq) {
					(Some(_), Some(value)) => format!("MODSEQ ({value}) "),
					_ => String::new(),
				};
				if uidonly {
					// UIDONLY: the UID leads the UIDFETCH response, not a data item.
					response.push_str(&format!(
						"* UIDFETCH {message_uid} ({modseq}FLAGS {stored_render})\r\n"
					));
				} else {
					let uid_part = if uid {
						format!("UID {message_uid} ")
					} else {
						String::new()
					};
					response.push_str(&format!(
						"* {sequence_number} FETCH ({uid_part}{modseq}FLAGS {stored_render})\r\n"
					));
				}
			}
		}
		// Compare the keyword set after `store_flags` against the
		// pre-loop snapshot. Only the genuinely new keywords need
		// advertising: STORE -FLAGS on the last message carrying a
		// keyword leaves the mailbox keyword set unchanged, and
		// emitting a redundant FLAGS line in that case would just be
		// more bytes on the wire.
		let post_keywords = collect_mailbox_keywords(snapshot);
		let newly_added: Vec<String> = post_keywords
			.into_iter()
			.filter(|name| {
				!pre_keywords
					.iter()
					.any(|existing| existing.eq_ignore_ascii_case(name))
			})
			.collect();
		let prelude = if newly_added.is_empty() {
			String::new()
		} else {
			format!("* {}", flags_line_for(&newly_added))
		};
		response = format!("{prelude}{response}");
		let code = if modified.is_empty() {
			String::new()
		} else {
			format!("[MODIFIED {}] ", super::codes::uid_set(&modified))
		};
		response.push_str(&format!("{tag} OK {code}STORE completed\r\n"));
		Output::text(response)
	}
}
