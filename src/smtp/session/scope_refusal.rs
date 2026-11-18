//! The refusals the antispam scopes' sender lists make at `RCPT TO`: a
//! sender a list denies, and a recipient an account may not write to. Both
//! are permanent `550 5.7.1` replies sent before any data, so nothing is
//! stored and no bounce goes to a forged sender.

use super::{Address, Reply, Resolution, Session, State};
use crate::antispam::scopes::Target;

impl Session {
	/// The reverse path of the open transaction.
	fn envelope_sender(&self) -> Option<&str> {
		match &self.state {
			State::ReceivingRecipients { reverse_path, .. }
			| State::ReceivingData { reverse_path, .. } => Some(reverse_path),
			_ => None,
		}
	}

	/// The refusal for `recipient`, which `resolution` found, when a sender
	/// list of the scopes in reach says so.
	///
	/// A client that has not authenticated is judged by the lists of the
	/// recipient it writes to: a deny entry naming its envelope sender
	/// refuses it. An authenticated account is judged by the lists of its
	/// own scopes: a `deny_recipients` entry naming the recipient refuses
	/// it. The null reverse path matches no entry.
	pub(super) fn scope_refusal(
		&self,
		recipient: &Address,
		resolution: &Resolution,
	) -> Option<Reply> {
		let scopes = self.policy.scopes()?;
		let sender = self.envelope_sender()?;
		// What the recipient check answers for itself comes first: an
		// address that does not exist, and a relay nobody may use.
		match (resolution, self.authenticated.is_some()) {
			(Resolution::UnknownUser, _) | (Resolution::NotLocal, false) => return None,
			_ => {}
		}
		match self.authenticated.as_deref() {
			None => {
				let accounts = match resolution {
					Resolution::Account(account) => vec![account.clone()],
					Resolution::Alias(members) => members.clone(),
					_ => Vec::new(),
				};
				Target::of_recipient(recipient.domain(), &accounts)
					.iter()
					.any(|target| scopes.refuses_sender(sender, target))
					.then(|| {
						tracing::info!(%recipient, "refused at RCPT: the sender is on a deny list");
						Reply::single(550, "5.7.1 sender not accepted for this recipient")
					})
			}
			Some(account) => {
				// The scopes of the account's own domains, from the
				// directory: the envelope sender is the client's to write
				// and decides nothing here.
				let mut domains: Vec<String> = self
					.directory
					.addresses_for(account)
					.iter()
					.filter_map(|address| Some(address.rsplit_once('@')?.1.to_ascii_lowercase()))
					.collect();
				domains.sort();
				domains.dedup();
				if domains.is_empty() {
					domains.push(String::new());
				}
				let recipient = recipient.to_string();
				domains
					.iter()
					.map(|domain| Target {
						domain: domain.clone(),
						account: Some(account.to_string()),
					})
					.any(|target| scopes.refuses_recipient(&recipient, &target))
					.then(|| {
						tracing::info!(%recipient, %account, "refused at RCPT: the recipient is on a deny list");
						Reply::single(550, "5.7.1 sending to this recipient is not allowed")
					})
			}
		}
	}
}
