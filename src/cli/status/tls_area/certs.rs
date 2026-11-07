//! The certificates container, when the stack runs one: whether it runs,
//! and what its absence means for the certificate `mail` presents.
//!
//! With `certs` down nothing renews: `mail` keeps serving the certificate it
//! has until it expires, so the item names the container's state and the
//! days the certificate has left, and fails when those days are few.
//!
//! A container that keeps restarting is not up either. `podup ps` reports
//! "running" for a container that exits at start, because the restart policy
//! brings it back within a second, so the container is judged the way
//! `stack certs` judges it: two looks, and the start has to be the same in
//! both (`stack::certs::upness`).
//!
//! A container that stays up but renews nothing is not enough either. The
//! last failed attempt leaves its reason under `<data_dir>/acme/renew.error`,
//! and a pair on disk that is older than the window in which it had to be
//! renewed says the same without leaving a file behind.

use std::path::Path;

use super::super::report::{Item, Level};
use super::{DAY, FAIL_DAYS, plural};
use crate::cli::stack::certs::Upness;

/// What the renewal left behind that says it did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Renewal {
	/// The last attempt failed; this is the reason it gave.
	Failed(String),
	/// The pair on disk is older than the window in which it had to be
	/// renewed; this says when it was due.
	Stale(String),
}

impl Renewal {
	/// The text that says what stopped the renewal.
	fn why(&self) -> String {
		match self {
			Renewal::Failed(reason) => format!("the last renewal failed: {reason}"),
			Renewal::Stale(text) => format!("the certificate was not renewed: {text}"),
		}
	}
}

/// What the renewal left behind that says it did not happen: the reason the
/// last attempt gave, or a pair on disk that is older than the window in
/// which it had to be renewed.
///
/// `renew_before_days` is the window the configuration asks for; `None`
/// means the configuration has no `[acme]`, so there is no renewal to judge.
pub(super) fn renewal(
	data_dir: &Path,
	renew_before_days: Option<u64>,
	now: u64,
) -> Option<Renewal> {
	if let Some(error) = crate::acme::renew_request::last_error(data_dir)
		&& !error.trim().is_empty()
	{
		return Some(Renewal::Failed(reason(&error)));
	}
	let window = renew_before_days?;
	stale_pair(data_dir, window, now).map(Renewal::Stale)
}

/// The reason the last attempt gave, without the moment it was made.
fn reason(text: &str) -> String {
	let text = text.trim();
	match text.split_once(' ') {
		Some((stamp, rest)) if stamp.parse::<u64>().is_ok() => rest.trim().to_string(),
		_ => text.to_string(),
	}
}

/// The ACME pair on disk, when it is older than the window in which it had
/// to be renewed: the renewal was due at `notAfter - renew_before_days`, and
/// the pair has not been written since.
fn stale_pair(data_dir: &Path, renew_before_days: u64, now: u64) -> Option<String> {
	let cert = crate::acme::renew::cert_path(data_dir);
	let key = crate::acme::renew::key_path(data_dir);
	if !cert.is_file() || !key.is_file() {
		return None;
	}
	let leaf = match super::read_leaf(&cert) {
		Ok(leaf) => leaf,
		Err(error) => {
			return Some(format!(
				"the pair in {} cannot be read ({error})",
				cert.display()
			));
		}
	};
	let written = std::fs::metadata(&cert).ok()?.modified().ok()?;
	let written = written
		.duration_since(std::time::UNIX_EPOCH)
		.ok()?
		.as_secs();
	let not_after = u64::try_from(leaf.not_after).ok()?;
	let due = not_after.saturating_sub(renew_before_days.saturating_mul(86_400));
	if now < due || written >= due {
		return None;
	}
	let age = (now - written) / 86_400;
	let overdue = (now - due) / 86_400;
	Some(format!(
		"the pair was written {age} days ago and the renewal was due {overdue} days ago"
	))
}

/// The item for the certificates container, with `remaining` seconds left on
/// the certificate in service.
pub(super) fn item(upness: &Upness, renewal: Option<&Renewal>, remaining: i64) -> Item {
	let left = if remaining > 0 {
		format!("{} left", plural(remaining / DAY))
	} else {
		"already expired".to_string()
	};
	let level = |running: bool| {
		if remaining < FAIL_DAYS * DAY {
			Level::Fail
		} else if running {
			Level::Ok
		} else {
			Level::Warn
		}
	};
	match upness {
		Upness::Up => match renewal {
			None => Item::new(
				"certs",
				Level::Ok,
				format!("the certificates container renews the certificate; {left}"),
			),
			Some(renewal) => Item::new(
				"certs",
				level(false),
				format!(
					"the certificates container runs, but {}; {left}",
					renewal.why()
				),
			),
		},
		Upness::Down(text) => Item::new(
			"certs",
			level(false),
			format!(
				"the certificates container {text}, so nothing renews: mail serves the certificate \
				 it has, {left}; `epistle stack up` starts it"
			),
		),
		Upness::Unsteady(text) => Item::new(
			"certs",
			level(false),
			format!(
				"the certificates container {text}, so the renewal is not guaranteed: mail serves \
				 the certificate it has, {left}; `epistle stack logs certs` says why"
			),
		),
		Upness::Unreadable(error) => Item::new(
			"certs",
			level(false),
			format!(
				"the certificates container could not be read ({error}), so nothing renews: mail \
				 serves the certificate it has, {left}; `epistle stack up` starts it"
			),
		),
	}
}
