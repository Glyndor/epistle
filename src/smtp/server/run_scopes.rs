//! What the antispam scopes decide once a message has been received: whether
//! the sender is favoured, and the attachment settings of its recipients.
//! Split from `run_deliver.rs` to keep both under the code-line limit.

use crate::antispam::attachments::policy::Overlay;
use crate::antispam::scopes::{SpamNumbers, Target};
use crate::dmarc::author::{AuthorDomain, author_domain};
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;

use super::Server;

impl Server {
	/// The scopes of each recipient of `message`: its domain and, when one
	/// account owns the address, that account.
	fn recipient_targets(&self, message: &AcceptedMessage) -> Vec<Target> {
		let directory = self.directory.current();
		message
			.recipients
			.iter()
			.filter_map(|recipient| Address::parse(recipient).ok())
			.flat_map(|address| {
				let accounts = match directory.resolve(&address) {
					Resolution::Account(account) => vec![account],
					Resolution::Alias(members) => members,
					_ => Vec::new(),
				};
				Target::of_recipient(address.domain(), &accounts)
			})
			.collect()
	}

	/// Whether the sender lists favour `message`: an allow entry names its
	/// envelope sender for every recipient, and the server itself verified
	/// that sender.
	///
	/// Matching a list is never enough. The entry names the envelope
	/// sender, which anybody can write, so the answer is `false` unless
	/// `message.sender_verified` says this server's own SPF or DKIM checks
	/// passed for the sender's domain, and the `From` header names the same
	/// organization, so mail that only borrows a favoured address in its
	/// envelope is not favoured. A message that fails DMARC never reaches
	/// this point: it was refused before. What the answer lets through is
	/// only the score-based screens; it never skips authentication, the
	/// DNS blocklists, the virus scanner or the attachment policy.
	pub(super) fn sender_favoured(&self, message: &AcceptedMessage) -> bool {
		let Some(scopes) = self.scopes.as_deref().filter(|scopes| !scopes.is_inert()) else {
			return false;
		};
		if !message.sender_verified || message.reverse_path.is_empty() {
			return false;
		}
		// The envelope sender and the From domain are read the way the rest
		// of the server reads an address, so a variant spelling of either is
		// the same name here and in the lists.
		let Ok(envelope) = Address::parse(&message.reverse_path) else {
			return false;
		};
		let AuthorDomain::One(from) = author_domain(&message.data) else {
			return false;
		};
		let aligned = crate::domain::normalize(&from).is_ok_and(|from| {
			crate::dmarc::organizational_domain(envelope.domain())
				== crate::dmarc::organizational_domain(&from)
		});
		let targets = self.recipient_targets(message);
		aligned
			&& !targets.is_empty()
			&& targets
				.iter()
				.all(|target| scopes.favours_sender(&envelope.to_string(), target))
	}

	/// The thresholds and delays that apply to `message`: the server's own,
	/// with the tenant, domain and account of each recipient on top, and the
	/// strictest of the recipients' when there are several.
	pub(super) fn spam_numbers(&self, message: &AcceptedMessage) -> SpamNumbers {
		let server = SpamNumbers {
			junk_at: self.bayes_junk_at,
			reject_at: self.bayes_reject_at,
			greylist_delay_secs: self.greylist.as_ref().map_or(0, |(_, delay)| *delay),
			first_time_delay_secs: self.first_time_delay.as_secs(),
		};
		match self.scopes.as_deref().filter(|scopes| !scopes.is_inert()) {
			Some(scopes) => scopes.spam_numbers(&self.recipient_targets(message), server),
			None => server,
		}
	}

	/// The attachment settings the scopes of `message`'s recipients add to
	/// the server's policy.
	pub(super) fn attachment_overlay(&self, message: &AcceptedMessage) -> Overlay {
		match self.scopes.as_deref().filter(|scopes| !scopes.is_inert()) {
			Some(scopes) => scopes.attachment_overlay(&self.recipient_targets(message)),
			None => Overlay::default(),
		}
	}
}
