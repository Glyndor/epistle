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

/// Whether a local account that any of `recipients` delivers to has a
/// message-size cap below `size`: the same check SMTP runs for every
/// recipient, so the API and JMAP cannot send what SMTP would refuse. The
/// cap of the recipient is not told to the sender.
pub(crate) fn over_recipient_size_cap(state: &ApiState, recipients: &[String], size: u64) -> bool {
	use crate::smtp::address::Address;
	use crate::smtp::directory::Resolution;
	let Some(directory) = state.directory_snapshot() else {
		return false;
	};
	recipients
		.iter()
		.filter_map(|recipient| Address::parse(recipient).ok())
		.any(|address| {
			let accounts: Vec<String> = match directory.resolve(&address) {
				Resolution::Account(account) => vec![account],
				Resolution::Alias(accounts) => accounts,
				Resolution::NotLocal | Resolution::UnknownUser => return false,
			};
			accounts
				.iter()
				.any(|account| directory.admit_message(account, size).is_err())
		})
}
