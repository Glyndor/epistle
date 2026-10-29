//! JMAP state strings and the `/changes` methods (RFC 8620 section 5.2).
//!
//! Every state is a position in the account's change journal
//! ([`crate::imap::changelog`]), which IMAP, POP3, SMTP delivery and JMAP all
//! write through the same mailbox operations. The wire form is
//! `base64url(kind || epoch || position)`: opaque to the client, identical
//! before and after a restart when nothing changed, and bound to the
//! journal's epoch so a state from another account, or from before the
//! account was re-created, is refused with `cannotCalculateChanges`.

use std::path::{Path, PathBuf};

use base64::Engine;
use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::fold::{Outcome, fold};
use crate::imap::changelog::{self, Entry, Object, Position, SinceError};

/// The type a state string belongs to; a state of one type is refused by
/// another type's `/changes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
	Email = 1,
	Mailbox = 2,
	Thread = 3,
}

/// A decoded state string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct State {
	pub kind: Kind,
	pub epoch: u64,
	pub position: u64,
}

impl State {
	pub(crate) fn encode(&self) -> String {
		let mut payload = [0u8; 17];
		payload[0] = self.kind as u8;
		payload[1..9].copy_from_slice(&self.epoch.to_be_bytes());
		payload[9..].copy_from_slice(&self.position.to_be_bytes());
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
	}

	/// `None` for anything that is not a state of `expected` this server
	/// minted: the caller answers `cannotCalculateChanges`.
	pub(crate) fn decode(value: &str, expected: Kind) -> Option<Self> {
		let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
			.decode(value)
			.ok()?;
		let payload: [u8; 17] = bytes.try_into().ok()?;
		if payload[0] != expected as u8 {
			return None;
		}
		Some(Self {
			kind: expected,
			epoch: u64::from_be_bytes(payload[1..9].try_into().ok()?),
			position: u64::from_be_bytes(payload[9..].try_into().ok()?),
		})
	}
}

/// The account's data directory (`<data_dir>/accounts/<name>`).
pub(crate) fn account_root(data_dir: &Path, account: &str) -> Option<PathBuf> {
	let name = crate::util::path_component::AccountName::new(account).ok()?;
	name.root(data_dir)
		.ok()
		.map(|root| root.as_path().to_path_buf())
}

/// The current state string of `kind` for `account`.
pub(crate) fn current_state(data_dir: &Path, account: &str, kind: Kind) -> Option<String> {
	let position = changelog::current(&account_root(data_dir, account)?).ok()?;
	Some(
		State {
			kind,
			epoch: position.epoch,
			position: position.current,
		}
		.encode(),
	)
}

pub(crate) fn email_get_state(data_dir: &Path, account: &str) -> Option<String> {
	current_state(data_dir, account, Kind::Email)
}

pub(crate) fn mailbox_get_state(data_dir: &Path, account: &str) -> Option<String> {
	current_state(data_dir, account, Kind::Mailbox)
}

pub(crate) fn thread_get_state(data_dir: &Path, account: &str) -> Option<String> {
	current_state(data_dir, account, Kind::Thread)
}

fn error(kind: &str, call_id: &str) -> Value {
	json!(["error", { "type": kind }, call_id])
}

/// The `accountId` argument, once the principal is allowed to see it.
pub(super) fn admitted_account(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Result<String, Value> {
	let account = args
		.get("accountId")
		.and_then(Value::as_str)
		.ok_or_else(|| error("invalidArguments", call_id))?;
	let view = state
		.accounts()
		.into_iter()
		.find(|a| a.name == account)
		.ok_or_else(|| error("accountNotFound", call_id))?;
	if !principal.admits_account(&view.name, &view.addresses) {
		return Err(error("accountNotFound", call_id));
	}
	Ok(view.name)
}

/// `maxChanges`: absent or null means no limit; anything but a positive
/// integer is `invalidArguments` (RFC 8620 section 5.2).
pub(super) fn max_changes(args: &Value, call_id: &str) -> Result<Option<usize>, Value> {
	match args.get("maxChanges") {
		None | Some(Value::Null) => Ok(None),
		Some(value) => value
			.as_u64()
			.filter(|max| *max > 0)
			.map(|max| Some(usize::try_from(max).unwrap_or(usize::MAX)))
			.ok_or_else(|| error("invalidArguments", call_id)),
	}
}

/// The journal entries after the client's state `value` of `kind`, or the
/// `cannotCalculateChanges` error when the state is not one the journal can
/// answer (malformed, another type or epoch, trimmed, or ahead of it).
pub(super) fn entries_since(
	state: &ApiState,
	account: &str,
	value: &str,
	kind: Kind,
	call_id: &str,
) -> Result<(State, Position, Vec<Entry>), Value> {
	let since =
		State::decode(value, kind).ok_or_else(|| error("cannotCalculateChanges", call_id))?;
	let root =
		account_root(state.data_dir(), account).ok_or_else(|| error("accountNotFound", call_id))?;
	match changelog::since(&root, since.epoch, since.position) {
		Ok((position, entries)) => Ok((since, position, entries)),
		Err(SinceError::Unknown) => Err(error("cannotCalculateChanges", call_id)),
		Err(SinceError::Io(io_error)) => {
			tracing::warn!(error = %io_error, "could not read the JMAP change journal");
			Err(error("serverFail", call_id))
		}
	}
}

/// `Mailbox/changes`, `Email/changes`, `Thread/changes`.
pub(super) fn changes(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	method: &str,
) -> Value {
	match changes_reply(state, principal, args, call_id, method) {
		Ok(reply) | Err(reply) => reply,
	}
}

fn changes_reply(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	method: &str,
) -> Result<Value, Value> {
	let account = admitted_account(state, principal, args, call_id)?;
	let (kind, object) = match method {
		"Email/changes" => (Kind::Email, Object::Email),
		"Thread/changes" => (Kind::Thread, Object::Email),
		"Mailbox/changes" => (Kind::Mailbox, Object::Mailbox),
		_ => return Err(error("unknownMethod", call_id)),
	};
	let max = max_changes(args, call_id)?;
	// A missing state is one the server cannot answer from either.
	let since_value = args.get("sinceState").and_then(Value::as_str).unwrap_or("");
	let (since, position, entries) = entries_since(state, &account, since_value, kind, call_id)?;
	let folded = fold(
		&entries,
		object,
		max,
		kind == Kind::Thread,
		position.current,
	);
	let new_state = State {
		position: folded.through,
		..since
	};
	let updated = folded.ids(|o| matches!(o, Outcome::Updated { .. }));
	let mut reply = json!({
		"accountId": account,
		"oldState": since_value,
		"newState": new_state.encode(),
		"hasMoreChanges": folded.has_more,
		"created": folded.ids(|o| o == Outcome::Created),
		"updated": updated,
		"destroyed": folded.ids(|o| o == Outcome::Destroyed),
	});
	if kind == Kind::Mailbox {
		// RFC 8621 section 2.2: when only the counts of the updated
		// mailboxes changed, say so, so the client refetches just those.
		let counts_only = !updated.is_empty()
			&& folded.outcomes.iter().all(|(_, outcome)| match outcome {
				Outcome::Updated { only_updates } => *only_updates,
				_ => true,
			});
		reply["updatedProperties"] = if counts_only {
			json!([
				"totalEmails",
				"unreadEmails",
				"totalThreads",
				"unreadThreads"
			])
		} else {
			Value::Null
		};
	}
	Ok(json!([method, reply, call_id]))
}

#[cfg(test)]
mod tests;
