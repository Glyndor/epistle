//! What a dry run of `POST /api/v1/send` spends and what it may look at.
//!
//! A dry run costs nothing to the sending limits, so without a limit of its
//! own it would tell any key which addresses are suppressed and which local
//! mailboxes are full, as often as it likes. It is charged per account, one
//! unit per recipient, on a minute and, for the addresses the account never
//! wrote to, on a day; and it looks only at the mailboxes the key reaches.

use std::sync::Arc;

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::ratelimit::WindowLimiter;

/// Recipients one account may dry-run in a minute.
pub const PER_MINUTE: u32 = 600;

/// Addresses the account never wrote to that it may dry-run in a day.
pub const NEW_PER_DAY: u32 = 1000;

/// The two windows a dry run is charged to.
#[derive(Debug, Clone)]
pub struct Limits {
	pub(crate) minute: Arc<WindowLimiter>,
	pub(crate) day: Arc<WindowLimiter>,
	pub(crate) per_minute: u32,
	pub(crate) new_per_day: u32,
}

impl Limits {
	/// Windows of a minute and a day with the caps given.
	pub fn new(per_minute: u32, new_per_day: u32) -> Self {
		Self {
			minute: Arc::new(WindowLimiter::for_authenticated_keys(60)),
			day: Arc::new(WindowLimiter::for_authenticated_keys(24 * 60 * 60)),
			per_minute,
			new_per_day,
		}
	}
}

impl Default for Limits {
	fn default() -> Self {
		Self::new(PER_MINUTE, NEW_PER_DAY)
	}
}

/// Charge a dry run of `recipients` to `account`, or refuse it with the
/// wait. Nothing stays charged by a refusal.
pub(super) fn charge(
	state: &ApiState,
	account: &str,
	recipients: &[String],
	now: u64,
) -> Result<(), ApiError> {
	let limits = state.dry_run_limits();
	let units = u32::try_from(recipients.len()).unwrap_or(u32::MAX);
	let refused = |until: u64| {
		ApiError::rate_limited_with_message(
			"too many dry runs for this account; retry later",
			until.saturating_sub(now).max(1),
		)
	};
	if !limits
		.minute
		.check_n(account, units, limits.per_minute, now)
	{
		return Err(refused(limits.minute.retry_at(account, now)));
	}
	let refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
	let unknown = match state.correspondents() {
		Some(store) => store.unknown_count(account, &refs).unwrap_or(units),
		None => units,
	};
	if !limits
		.day
		.check_n(account, unknown, limits.new_per_day, now)
	{
		limits.minute.refund(account, units, now);
		return Err(refused(limits.day.retry_at(account, now)));
	}
	Ok(())
}

/// The local recipients among `recipients` that `principal` reaches: the
/// only ones whose mailboxes a dry run may measure. A remote address, or a
/// local one of an account the key does not reach, is left out, so the
/// answer says nothing about it.
pub(super) fn reachable(
	state: &ApiState,
	principal: &Principal,
	recipients: &[String],
) -> Vec<String> {
	let Some(directory) = state.directory_snapshot() else {
		return Vec::new();
	};
	let views = state.accounts();
	let reaches = |name: &str| {
		views
			.iter()
			.find(|view| view.name == name)
			.is_some_and(|view| principal.admits_account(&view.name, &view.addresses))
	};
	recipients
		.iter()
		.filter(|recipient| {
			let Ok(address) = Address::parse(recipient) else {
				return false;
			};
			match directory.resolve(&address) {
				Resolution::Account(name) => reaches(&name),
				// The members an alias resolves to are those that can receive, so
				// what is measured would change with the state of an account
				// the key does not reach: a confined key does not measure aliases.
				Resolution::Alias(names) => {
					principal.is_unrestricted() && names.iter().all(|name| reaches(name))
				}
				Resolution::NotLocal | Resolution::UnknownUser => false,
			}
		})
		.cloned()
		.collect()
}
