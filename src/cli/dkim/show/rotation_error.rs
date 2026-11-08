//! The last failed rotation as `dkim show` prints it.
//!
//! The server writes `<epoch seconds> <reason>` when it withdraws a rotation
//! and removes the line only when a later rotation succeeds, so a failure from
//! months ago stays in the file until then. A failure older than the key now
//! signing is not news: that rotation was replaced by a good one.

use crate::clock::rfc3339_or_epoch;

/// The error line worth showing, with its time in the same form as the other
/// timestamps, or `None` when there is none or a later rotation superseded it.
pub(super) fn current(raw: Option<String>, rotated_at: Option<u64>) -> Option<String> {
	let raw = raw?;
	let raw = raw.trim();
	let Some((first, reason)) = raw.split_once(' ') else {
		return Some(raw.to_string()).filter(|text| !text.is_empty());
	};
	let Ok(at) = first.parse::<u64>() else {
		return Some(raw.to_string());
	};
	if rotated_at.is_some_and(|rotated| rotated >= at) {
		return None;
	}
	Some(format!("{} ({})", reason.trim(), rfc3339_or_epoch(at)))
}
