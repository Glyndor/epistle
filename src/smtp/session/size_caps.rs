//! The message-size caps of the accounts a transaction concerns, below the
//! server's `max_message_size`: the sender's own cap when it authenticated,
//! and the cap of every account a recipient delivers to.
//!
//! A sender that declares a `SIZE` is refused as soon as it is known: at
//! `MAIL FROM` for its own cap, at `RCPT TO` for that recipient only (RFC
//! 1870, RFC 5321 section 4.5.3.1.7). A message whose real size is past the
//! cap of the sender or of any recipient, which a sender that understated
//! `SIZE` can still send, is refused whole at the end of the data. Every
//! refusal is `552 5.3.4`. The sender is told its own cap and the scope that
//! set it; the cap of a recipient is not told to a stranger.

use super::{Address, Reply, Resolution, Session};

impl Session {
	/// The refusal for a declared `size` over the cap of the account that
	/// authenticated, if there is one.
	pub(super) fn sender_size_refusal(&self, size: Option<u64>) -> Option<Reply> {
		let (account, size) = self.authenticated.as_deref().zip(size)?;
		let reached = self.directory.admit_message(account, size).err()?;
		reached.log(account);
		Some(Reply::single(552, &format!("5.3.4 {reached}")))
	}

	/// The refusal for the declared size of the open transaction when an
	/// account `resolution` delivers to cannot take a message that big.
	pub(super) fn recipient_size_refusal(&self, resolution: &Resolution) -> Option<Reply> {
		let size = self.declared_size?;
		self.over_recipient_cap(resolution, size)
			.then(recipient_refusal)
	}

	/// The refusal at the end of the data for a message of `size` bytes, when
	/// the cap of its sender or of any recipient is below it.
	pub(super) fn size_refusal(&self, recipients: &[String], size: usize) -> Option<Reply> {
		let size = size as u64;
		if let Some(reply) = self.sender_size_refusal(Some(size)) {
			return Some(reply);
		}
		recipients
			.iter()
			.filter_map(|recipient| Address::parse(recipient).ok())
			.any(|address| self.over_recipient_cap(&self.directory.resolve(&address), size))
			.then(recipient_refusal)
	}

	/// Whether an account `resolution` delivers to has a cap below `size`.
	fn over_recipient_cap(&self, resolution: &Resolution, size: u64) -> bool {
		let accounts: &[String] = match resolution {
			Resolution::Account(account) => std::slice::from_ref(account),
			Resolution::Alias(accounts) => accounts,
			Resolution::NotLocal | Resolution::UnknownUser => return false,
		};
		accounts
			.iter()
			.any(|account| self.directory.admit_message(account, size).is_err())
	}
}

fn recipient_refusal() -> Reply {
	Reply::single(
		552,
		"5.3.4 message exceeds the size limit of a recipient of this server",
	)
}
