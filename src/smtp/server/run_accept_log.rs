//! The log line that records an accepted inbound message.
//!
//! A message the server accepted is the fact an operator cannot see
//! anywhere else: the Maildir shows the message afterwards and the
//! metrics show a counter, but the log said nothing at the default
//! level, so "did my mail arrive?" had no answer in the log.
//!
//! The line names the account the message goes to by its log pseudonym
//! (`acct-<12 hex>`), never by its name and never by an address. The
//! operator maps the pseudonym back with `epistle account find-log-id`.

use crate::smtp::session::AcceptedMessage;

use super::Server;

impl Server {
	/// What the line about an accepted message carries: the account the
	/// message goes to as its log pseudonym, the octets of the message
	/// and how many recipients the envelope named.
	///
	/// The recipient is an address and never reaches the log: only the
	/// pseudonym of the account it belongs to does. An address that does
	/// not resolve to a local account leaves the line without a
	/// pseudonym (`unknown`): the message was accepted for a domain
	/// this server does not serve, and the line says so.
	pub(super) fn accepted_record(
		&self,
		message: &AcceptedMessage,
	) -> crate::smtp::session_log::Accepted {
		let log_id = message
			.recipients
			.iter()
			.find_map(|recipient| self.account_pseudonym(recipient))
			.unwrap_or_else(|| crate::smtp::session_log::UNKNOWN.to_string());
		crate::smtp::session_log::Accepted {
			log_id,
			size: message.data.len() as u64,
			recipients: message.recipients.len() as u64,
		}
	}

	/// The log pseudonym of the account an address belongs to, or `None`
	/// when the address is not served here.
	fn account_pseudonym(&self, address: &str) -> Option<String> {
		let Ok(address) = crate::smtp::address::Address::parse(address) else {
			return None;
		};
		match self.directory.current().resolve(&address) {
			crate::smtp::directory::Resolution::Account(account) => {
				Some(crate::log_id::account(&account))
			}
			crate::smtp::directory::Resolution::Alias(accounts) => accounts
				.first()
				.map(|account| crate::log_id::account(account)),
			crate::smtp::directory::Resolution::NotLocal
			| crate::smtp::directory::Resolution::UnknownUser => None,
		}
	}
}
