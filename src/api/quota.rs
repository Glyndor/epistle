//! Mailbox quota of the local recipients of an API or JMAP submission.
//!
//! These paths queue the message, so a full local mailbox would only
//! surface days later as a bounce. They refuse the request instead, with
//! the same measure IMAP QUOTA and SMTP use (see [`crate::smtp::quota`]).

use super::state::ApiState;
use crate::smtp::quota::MailboxQuota;

/// The first of `recipients` that is a local account a message of `size`
/// bytes would put over its quota.
pub(crate) fn full_recipient(state: &ApiState, recipients: &[String], size: u64) -> Option<String> {
	let directory = state.directory_snapshot()?;
	let quota = MailboxQuota::on_disk(
		state.data_dir().to_path_buf(),
		state.crypto().clone(),
		state.quota_limit(),
	);
	quota
		.overflowing(&directory, recipients, size)
		.into_iter()
		.next()
}
